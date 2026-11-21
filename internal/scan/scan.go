// Package scan decides per container whether a rule applies: CPU feature on
// the node, affected JDK and no mitigation flag.
package scan

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/simonliska/java4shell-k8s-scanner/internal/javaver"
	"github.com/simonliska/java4shell-k8s-scanner/internal/rules"
)

type Status string

const (
	Exposed     Status = "EXPOSED"      // affected JDK, CPU feature, no mitigation
	AtRisk      Status = "AT RISK"      // could become exposed (rescheduling, unknown CPU or JDK)
	Mitigated   Status = "MITIGATED"    // affected JDK, but a mitigation flag is active
	NotExposed  Status = "NOT EXPOSED"  // affected JDK, but no node with the CPU feature can run it
	NotAffected Status = "NOT AFFECTED" // JDK outside the affected ranges
)

// Statuses lists all statuses, most urgent first.
var Statuses = []Status{Exposed, AtRisk, Mitigated, NotExposed, NotAffected}

var severity = map[Status]int{Exposed: 0, AtRisk: 1, Mitigated: 2, NotExposed: 3, NotAffected: 4}

type Input struct {
	Nodes  []corev1.Node
	Pods   []corev1.Pod
	Probes map[ContainerRef]Probe // results of --exec; nil for a read-only scan
}

type ContainerRef struct {
	Namespace, Pod, Container string
}

type Finding struct {
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Workload   string `json:"workload"` // e.g. deployment/web, or pod/name for bare pods
	Container  string `json:"container"`
	Node       string `json:"node"` // "" while pending
	Image      string `json:"image"`
	CPU        CPU    `json:"cpu"`        // does the node have the CPU feature
	JDK        string `json:"jdk"`        // "" when unknown
	JDKSource  string `json:"jdkSource"`  // "exec", "image tag" or ""
	Mitigation string `json:"mitigation"` // active mitigation, "" if none
	Status     Status `json:"status"`
	Note       string `json:"note,omitempty"`

	multiContainer bool
}

// Label is the pod name, plus the container name if the pod has several.
func (f Finding) Label() string {
	if f.multiContainer {
		return fmt.Sprintf("%s (%s)", f.Pod, f.Container)
	}
	return f.Pod
}

type Result struct {
	Rule      rules.Rule `json:"rule"`
	Nodes     []NodeInfo `json:"nodes"`
	Workloads []Workload `json:"workloads"`
	Findings  []Finding  `json:"findings"` // one per pod and container
}

func (r Result) Count(s Status) int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == s {
			n++
		}
	}
	return n
}

// Analyze evaluates one rule against all Java containers.
func Analyze(rule rules.Rule, in Input) Result {
	nodes := classifyNodes(in.Nodes, rule.CPUFeature.NodeLabel)
	res := Result{Rule: rule, Nodes: nodes}

	cpuByNode := map[string]CPU{}
	var candidates []*corev1.Node // nodes that have, or may have, the CPU feature
	for i, n := range nodes {
		cpuByNode[n.Name] = n.CPU
		if n.CPU != CPUNo {
			candidates = append(candidates, &in.Nodes[i])
		}
	}

	for i := range in.Pods {
		pod := &in.Pods[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range pod.Spec.Containers {
			f, ok := evaluate(rule, pod, c, in.Probes)
			if !ok {
				continue // not a Java container
			}
			f.multiContainer = len(pod.Spec.Containers) > 1
			f.CPU = cpuByNode[pod.Spec.NodeName]
			if pod.Spec.NodeName == "" {
				f.CPU = CPUUnknown
			}
			decide(&f, rule, pod, candidates)
			res.Findings = append(res.Findings, f)
		}
	}

	slices.SortFunc(res.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(severity[a.Status], severity[b.Status]),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Pod, b.Pod),
			cmp.Compare(a.Container, b.Container),
		)
	})
	res.Workloads = group(res.Findings)
	return res
}

// evaluate collects JDK version and mitigation for one container.
// ok is false when the container does not run Java.
func evaluate(rule rules.Rule, pod *corev1.Pod, c corev1.Container, probes map[ContainerRef]Probe) (Finding, bool) {
	f := Finding{
		Namespace: pod.Namespace,
		Pod:       pod.Name,
		Workload:  workloadOf(pod),
		Container: c.Name,
		Node:      pod.Spec.NodeName,
		Image:     c.Image,
	}

	probe, probed := probes[ContainerRef{pod.Namespace, pod.Name, c.Name}]
	probeOK := probed && probe.Err == nil
	if !probeOK && !looksLikeJava(c) {
		return f, false
	}

	if probeOK && probe.Version != "" {
		f.JDK, f.JDKSource = probe.Version, "exec"
	} else if v := imageVersion(c.Image); v != "" {
		f.JDK, f.JDKSource = v, "image tag"
	}

	// The probe JVM sees the env (JAVA_TOOL_OPTIONS) but not the app's own
	// command-line flags, so check the spec too.
	if probeOK {
		f.Mitigation, _ = rule.MitigationInFlags(probe.Flags)
	}
	if f.Mitigation == "" {
		f.Mitigation, _ = rule.MitigationInArgs(jvmOptions(c))
	}

	if probed && !probeOK {
		f.Note = "exec failed: " + firstLine(probe.Err.Error())
	}
	return f, true
}

// decide sets Status and Note from the collected facts.
func decide(f *Finding, rule rules.Rule, pod *corev1.Pod, candidates []*corev1.Node) {
	var version javaver.Version
	if f.JDK != "" {
		if v, err := javaver.Parse(f.JDK); err == nil {
			version = v
		}
	}
	feature := rule.CPUFeature.Name

	switch {
	case version != nil && !rule.Affects(version):
		f.Status = NotAffected

	case f.Mitigation != "":
		f.Status = Mitigated

	case f.CPU == CPUYes && version != nil:
		f.Status = Exposed

	case f.CPU == CPUYes:
		f.Status = AtRisk // JDK version unknown; noted below

	case f.CPU == CPUUnknown && f.Node != "":
		f.Status = AtRisk
		addNote(f, "CPU features of node unknown (is Node Feature Discovery installed?)")

	case canMoveTo(pod, candidates):
		f.Status = AtRisk
		addNote(f, "can be scheduled on a node with "+feature)

	default:
		f.Status = NotExposed
		addNote(f, "no node with "+feature+" can run this pod")
	}

	if version == nil {
		addNote(f, "JDK version unknown (use --exec)")
	}
}

func addNote(f *Finding, note string) {
	if f.Note != "" {
		f.Note += "; "
	}
	f.Note += note
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

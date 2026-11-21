package scan

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// Workload sums up one container of a Deployment, StatefulSet etc. over all
// its pods, since a fix goes into the pod template.
type Workload struct {
	Namespace  string         `json:"namespace"`
	Name       string         `json:"name"` // e.g. deployment/web
	Container  string         `json:"container"`
	Pods       int            `json:"pods"`
	OnFeature  int            `json:"podsOnFeatureNodes"` // pods on nodes with the CPU feature
	JDK        string         `json:"jdk"`
	Mitigation string         `json:"mitigation"`
	Status     Status         `json:"status"` // worst status of its pods
	Statuses   map[Status]int `json:"statuses"`
	Note       string         `json:"note,omitempty"`

	multiContainer bool
}

// Label is the workload name, plus the container name if the pods have several.
func (w Workload) Label() string {
	if w.multiContainer {
		return fmt.Sprintf("%s (%s)", w.Name, w.Container)
	}
	return w.Name
}

// CountWorkloads counts workloads by their worst status.
func (r Result) CountWorkloads(s Status) int {
	n := 0
	for _, w := range r.Workloads {
		if w.Status == s {
			n++
		}
	}
	return n
}

// workloadOf names the pod's top-level owner. A Deployment's ReplicaSet is
// named <deployment>-<pod-template-hash>, so no extra API call is needed.
func workloadOf(pod *corev1.Pod) string {
	for _, o := range pod.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]; o.Kind == "ReplicaSet" && hash != "" {
			if name, ok := strings.CutSuffix(o.Name, "-"+hash); ok {
				return "deployment/" + name
			}
		}
		return strings.ToLower(o.Kind) + "/" + o.Name
	}
	return "pod/" + pod.Name
}

// group merges findings into one entry per workload and container.
func group(findings []Finding) []Workload {
	var keys [][3]string
	byKey := map[[3]string][]Finding{}
	for _, f := range findings {
		k := [3]string{f.Namespace, f.Workload, f.Container}
		if _, ok := byKey[k]; !ok {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], f)
	}

	out := make([]Workload, len(keys))
	for i, k := range keys {
		out[i] = newWorkload(byKey[k])
	}
	slices.SortFunc(out, func(a, b Workload) int {
		return cmp.Or(
			cmp.Compare(severity[a.Status], severity[b.Status]),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Container, b.Container),
		)
	})
	return out
}

// newWorkload summarizes the findings of one workload's pods, sorted worst first.
func newWorkload(fs []Finding) Workload {
	w := Workload{
		Namespace: fs[0].Namespace, Name: fs[0].Workload, Container: fs[0].Container,
		Status: fs[0].Status, Statuses: map[Status]int{}, multiContainer: fs[0].multiContainer,
	}
	var jdks, mitigations []string
	notes := map[Status][]string{}
	for _, f := range fs {
		w.Pods++
		w.Statuses[f.Status]++
		if f.CPU == CPUYes {
			w.OnFeature++
		}
		jdks = addUnique(jdks, f.JDK)
		mitigations = addUnique(mitigations, f.Mitigation)
		if f.Note != "" {
			notes[f.Status] = addUnique(notes[f.Status], f.Note)
		}
	}
	w.JDK = joinValues(jdks, "?") // can differ during a rollout
	w.Mitigation = joinValues(mitigations, "-")
	w.Note = groupNote(w.Statuses, notes)
	return w
}

// groupNote returns the notes, prefixed with pod counts when the pods'
// statuses differ: "1 EXPOSED, 1 AT RISK: can be scheduled on ...".
func groupNote(statuses map[Status]int, notes map[Status][]string) string {
	var parts []string
	for _, s := range Statuses {
		n := statuses[s]
		if n == 0 {
			continue
		}
		note := strings.Join(notes[s], "; ")
		switch {
		case len(statuses) == 1:
			return note
		case note != "":
			parts = append(parts, fmt.Sprintf("%d %s: %s", n, s, note))
		default:
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

func addUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// joinValues returns the shared value, or all values if pods differ.
func joinValues(values []string, placeholder string) string {
	if len(values) == 1 {
		return values[0]
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = cmp.Or(v, placeholder)
	}
	return strings.Join(out, ", ")
}

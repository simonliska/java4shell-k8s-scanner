package scan

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	corev1helpers "k8s.io/component-helpers/scheduling/corev1"
	"k8s.io/component-helpers/scheduling/corev1/nodeaffinity"
	"k8s.io/klog/v2"
)

// CPU says whether a node's CPU has the rule's feature.
type CPU string

const (
	CPUYes     CPU = "yes"
	CPUNo      CPU = "no"
	CPUUnknown CPU = "unknown" // no NFD CPU labels on the node
)

type NodeInfo struct {
	Name string `json:"name"`
	Arch string `json:"arch"`
	CPU  CPU    `json:"cpu"`
}

func classifyNodes(nodes []corev1.Node, label string) []NodeInfo {
	out := make([]NodeInfo, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		out[i] = NodeInfo{Name: n.Name, Arch: n.Labels[corev1.LabelArchStable], CPU: nodeCPU(n, label)}
	}
	return out
}

// nodeCPU reads the NFD label. NFD never writes "false", so a missing label
// means "no" only if NFD labelled the node at all.
func nodeCPU(n *corev1.Node, label string) CPU {
	if n.Labels[label] == "true" {
		return CPUYes
	}
	if arch := n.Labels[corev1.LabelArchStable]; arch != "" && arch != "amd64" {
		return CPUNo // x86 CPU features can't exist on arm64 etc.
	}
	prefix := label[:strings.LastIndex(label, ".")+1] // feature.node.kubernetes.io/cpu-cpuid.
	for k := range n.Labels {
		if strings.HasPrefix(k, prefix) {
			return CPUNo
		}
	}
	return CPUUnknown
}

// canMoveTo reports whether the pod could land on another candidate node.
// A running pod only moves when its owner (e.g. a ReplicaSet) recreates it.
func canMoveTo(pod *corev1.Pod, candidates []*corev1.Node) bool {
	if pod.Spec.NodeName != "" && len(pod.OwnerReferences) == 0 {
		return false // bare pods are not recreated elsewhere
	}
	for _, node := range candidates {
		if node.Name != pod.Spec.NodeName && fits(pod, node) {
			return true
		}
	}
	return false
}

// fits checks nodeSelector, required node affinity and NoSchedule/NoExecute taints.
func fits(pod *corev1.Pod, node *corev1.Node) bool {
	if ok, err := nodeaffinity.GetRequiredNodeAffinity(pod).Match(node); err != nil || !ok {
		return false
	}
	blocking := func(t *corev1.Taint) bool {
		return t.Effect == corev1.TaintEffectNoSchedule || t.Effect == corev1.TaintEffectNoExecute
	}
	// true: also honour Gt/Lt toleration operators.
	_, untolerated := corev1helpers.FindMatchingUntoleratedTaint(klog.Background(),
		node.Spec.Taints, pod.Spec.Tolerations, blocking, true)
	return !untolerated
}

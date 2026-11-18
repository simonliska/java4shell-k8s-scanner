package scan

import (
	"errors"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/simonliska/java4shell-k8s-scanner/internal/rules"
)

// Nodes mirror the AWS lab: t8i (Granite Rapids, VBMI) and t3 (Cascade Lake, AVX-512 but no VBMI).
const vbmiLabel = "feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI"

func node(name, arch string, labels map[string]string, taints ...corev1.Taint) corev1.Node {
	l := map[string]string{corev1.LabelArchStable: arch, corev1.LabelHostname: name}
	for k, v := range labels {
		l[k] = v
	}
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}, Spec: corev1.NodeSpec{Taints: taints}}
}

var (
	t8i = node("t8i", "amd64", map[string]string{vbmiLabel: "true", "feature.node.kubernetes.io/cpu-cpuid.AVX512F": "true"})
	t3  = node("t3", "amd64", map[string]string{"feature.node.kubernetes.io/cpu-cpuid.AVX512F": "true"})
	arm = node("arm", "arm64", nil)
)

type podOpt func(*corev1.Pod)

func pod(name, nodeName, image string, opts ...podOpt) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "lab",
			Name:            name,
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: name + "-rs"}},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "app", Image: image}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, o := range opts {
		o(&p)
	}
	return p
}

func withEnv(name, value string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, corev1.EnvVar{Name: name, Value: value})
	}
}

func withNodeSelector(k, v string) podOpt {
	return func(p *corev1.Pod) { p.Spec.NodeSelector = map[string]string{k: v} }
}

func bare() podOpt { return func(p *corev1.Pod) { p.OwnerReferences = nil } }

const (
	vulnImage  = "eclipse-temurin:21.0.13_9-jdk"
	fixedImage = "eclipse-temurin:21.0.13.1_1-jdk"
	oldImage   = "eclipse-temurin:17.0.5_8-jdk"
	appImage   = "quay.io/keycloak/keycloak:26.4" // Java, but the tag says nothing about the JDK
)

func java4shell(t *testing.T) rules.Rule {
	t.Helper()
	rs, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return rs[0]
}

func TestAnalyze(t *testing.T) {
	taintedT8i := node("t8i", "amd64", map[string]string{vbmiLabel: "true"},
		corev1.Taint{Key: "dedicated", Value: "db", Effect: corev1.TaintEffectNoSchedule})

	tests := []struct {
		name    string
		nodes   []corev1.Node
		pod     corev1.Pod
		probe   *Probe
		want    Status
		wantJDK string
	}{
		{name: "affected JDK on VBMI node", nodes: []corev1.Node{t8i, t3},
			pod: pod("p", "t8i", vulnImage), want: Exposed, wantJDK: "21.0.13"},
		{name: "mitigated via JAVA_TOOL_OPTIONS", nodes: []corev1.Node{t8i, t3},
			pod: pod("p", "t8i", vulnImage, withEnv("JAVA_TOOL_OPTIONS", "-XX:-UseBASE64Intrinsics")), want: Mitigated},
		{name: "fixed JDK", nodes: []corev1.Node{t8i},
			pod: pod("p", "t8i", fixedImage), want: NotAffected, wantJDK: "21.0.13.1"},
		{name: "JDK before affected range", nodes: []corev1.Node{t8i},
			pod: pod("p", "t8i", oldImage), want: NotAffected},
		{name: "on non-VBMI node but can be rescheduled to VBMI", nodes: []corev1.Node{t8i, t3},
			pod: pod("p", "t3", vulnImage), want: AtRisk},
		{name: "pinned to non-VBMI node by nodeSelector", nodes: []corev1.Node{t8i, t3},
			pod: pod("p", "t3", vulnImage, withNodeSelector(corev1.LabelHostname, "t3")), want: NotExposed},
		{name: "VBMI node tainted, pod has no toleration", nodes: []corev1.Node{taintedT8i, t3},
			pod: pod("p", "t3", vulnImage), want: NotExposed},
		{name: "bare pod is not recreated elsewhere", nodes: []corev1.Node{t8i, t3},
			pod: pod("p", "t3", vulnImage, bare()), want: NotExposed},
		{name: "arm64 cluster", nodes: []corev1.Node{arm},
			pod: pod("p", "arm", vulnImage), want: NotExposed},
		{name: "no NFD labels: CPU unknown", nodes: []corev1.Node{node("n", "amd64", nil)},
			pod: pod("p", "n", vulnImage), want: AtRisk},
		{name: "unknown JDK on VBMI node is not called EXPOSED", nodes: []corev1.Node{t8i},
			pod: pod("p", "t8i", appImage), want: AtRisk},
		{name: "exec finds affected JDK in app image", nodes: []corev1.Node{t8i},
			pod:   pod("p", "t8i", appImage),
			probe: &Probe{Version: "21.0.13", Flags: map[string]string{"UseBASE64Intrinsics": "true", "UseAVX": "3"}},
			want:  Exposed, wantJDK: "21.0.13"},
		{name: "exec sees mitigation set in the image (not in spec)", nodes: []corev1.Node{t8i},
			pod:   pod("p", "t8i", appImage),
			probe: &Probe{Version: "21.0.13", Flags: map[string]string{"UseBASE64Intrinsics": "false"}},
			want:  Mitigated},
		{name: "exec finds Java in an image without a Java-looking name", nodes: []corev1.Node{t8i},
			pod:   pod("p", "t8i", "registry.example.com/billing:1.2"),
			probe: &Probe{Version: "17.0.20", Flags: map[string]string{}},
			want:  Exposed},
		{name: "exec failed: fall back to the spec", nodes: []corev1.Node{t8i},
			pod:   pod("p", "t8i", vulnImage),
			probe: &Probe{Err: errors.New("forbidden")},
			want:  Exposed, wantJDK: "21.0.13"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := Input{Nodes: tt.nodes, Pods: []corev1.Pod{tt.pod}}
			if tt.probe != nil {
				in.Probes = map[ContainerRef]Probe{{"lab", "p", "app"}: *tt.probe}
			}
			res := Analyze(java4shell(t), in)
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(res.Findings))
			}
			f := res.Findings[0]
			if f.Status != tt.want {
				t.Errorf("status = %s (note: %q); want %s", f.Status, f.Note, tt.want)
			}
			if tt.wantJDK != "" && f.JDK != tt.wantJDK {
				t.Errorf("jdk = %q; want %q", f.JDK, tt.wantJDK)
			}
		})
	}
}

func TestAnalyzeSkipsNonJava(t *testing.T) {
	in := Input{Nodes: []corev1.Node{t8i}, Pods: []corev1.Pod{pod("web", "t8i", "nginx:1.29")}}
	if res := Analyze(java4shell(t), in); len(res.Findings) != 0 {
		t.Errorf("nginx reported: %+v", res.Findings)
	}
}

// Real output captured from the AWS lab (Temurin images, t8i node).
func TestParseProbe(t *testing.T) {
	tests := []struct {
		file, version, b64, avx string
	}{
		{"probe-mitigated", "21.0.13", "false", "3"},
		{"probe-17.0.5", "17.0.5", "true", "3"},
	}
	for _, tt := range tests {
		stdout, err1 := os.ReadFile("testdata/" + tt.file + ".stdout")
		stderr, err2 := os.ReadFile("testdata/" + tt.file + ".stderr")
		if err := errors.Join(err1, err2); err != nil {
			t.Fatal(err)
		}
		p := ParseProbe(string(stdout), string(stderr))
		if p.Version != tt.version || p.Flags["UseBASE64Intrinsics"] != tt.b64 || p.Flags["UseAVX"] != tt.avx {
			t.Errorf("%s: version=%q b64=%q avx=%q", tt.file, p.Version, p.Flags["UseBASE64Intrinsics"], p.Flags["UseAVX"])
		}
	}
}

func TestImageVersion(t *testing.T) {
	tests := map[string]string{
		"eclipse-temurin:21.0.13_9-jdk":            "21.0.13",
		"eclipse-temurin:17.0.21.1_1-jre-noble":    "17.0.21.1",
		"docker.io/library/eclipse-temurin:21-jdk": "", // moving tag
		"eclipse-temurin:21.0.13_9-jdk@sha256:abc": "21.0.13",
		"amazoncorretto:21.0.13.11.1":              "", // Corretto numbering differs
		"quay.io/keycloak/keycloak:26.4":           "",
		"localhost:5000/openjdk:17.0.2-jdk":        "17.0.2",
	}
	for image, want := range tests {
		if got := imageVersion(image); got != want {
			t.Errorf("imageVersion(%q) = %q; want %q", image, got, want)
		}
	}
}

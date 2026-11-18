package rules

import (
	"testing"

	"github.com/simonliska/java4shell-k8s-scanner/internal/javaver"
)

func builtin(t *testing.T) Rule {
	t.Helper()
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return rs[0]
}

func TestAffects(t *testing.T) {
	r := builtin(t)
	tests := map[string]bool{
		"17.0.5":      false, // before the intrinsic
		"17.0.6":      true,
		"17.0.21":     true,
		"17.0.21.0.3": true,  // Oracle's last affected build
		"17.0.21.1":   false, // first fixed build
		"21.0.13":     true,
		"21.0.13.1":   false,
		"25.0.5.1":    false,
		"26.0.2":      true, // EOL line, never fixed
		"27":          true,
		"27.0.1.1":    false,
		"11.0.25":     false,
		"1.8.0_511":   false,
	}
	for v, want := range tests {
		if got := r.Affects(javaver.MustParse(v)); got != want {
			t.Errorf("Affects(%s) = %v; want %v", v, got, want)
		}
	}
}

func TestMitigationInArgs(t *testing.T) {
	r := builtin(t)
	tests := []struct {
		args string
		want string // "" = not mitigated
	}{
		{"java -XX:-UseBASE64Intrinsics -jar app.jar", "-XX:-UseBASE64Intrinsics"},
		{"-XX:UseAVX=2", "-XX:UseAVX=2"},
		{"-XX:UseAVX=3", ""},
		{"-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics", ""}, // last one wins
		{"-XX:-UseBASE64IntrinsicsX", ""},                         // different flag
		{"java -jar app.jar", ""},
	}
	for _, tt := range tests {
		got, _ := r.MitigationInArgs(tt.args)
		if got != tt.want {
			t.Errorf("MitigationInArgs(%q) = %q; want %q", tt.args, got, tt.want)
		}
	}
}

func TestMitigationInFlags(t *testing.T) {
	r := builtin(t)
	if m, ok := r.MitigationInFlags(map[string]string{"UseBASE64Intrinsics": "false", "UseAVX": "3"}); !ok || m != "UseBASE64Intrinsics=false" {
		t.Errorf("got %q, %v", m, ok)
	}
	if m, ok := r.MitigationInFlags(map[string]string{"UseBASE64Intrinsics": "true", "UseAVX": "2"}); !ok || m != "UseAVX=2" {
		t.Errorf("got %q, %v", m, ok)
	}
	if _, ok := r.MitigationInFlags(map[string]string{"UseBASE64Intrinsics": "true", "UseAVX": "3"}); ok {
		t.Error("defaults should not count as mitigated")
	}
}

func TestParseRejectsBadRange(t *testing.T) {
	_, err := Parse([]byte(`
id: x
cpuFeature: {name: f, nodeLabel: l}
affected: [{from: "21.0.5", fixed: "17.0.1"}]
`))
	if err == nil {
		t.Error("want error for fixed version in a different major")
	}
}

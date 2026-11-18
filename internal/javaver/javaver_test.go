package javaver

import "testing"

func TestParse(t *testing.T) {
	tests := map[string]string{
		"21.0.13":       "21.0.13",
		"17.0.21.0.3":   "17.0.21.0.3", // Oracle build
		"27":            "27",
		"21.0.13+9-LTS": "21.0.13",
		"1.8.0_511":     "8.0.511", // legacy scheme
		"25-ea":         "25",
	}
	for in, want := range tests {
		v, err := Parse(in)
		if err != nil || v.String() != want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "LTS"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): want error", bad)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"21.0.13", "21.0.13.1", -1},
		{"21.0.13.0.3", "21.0.13.1", -1}, // last affected Oracle build < first fix
		{"21.0.13", "21.0.13.0", 0},
		{"17.0.10", "17.0.9", 1}, // numeric, not string, comparison
		{"27", "27.0.1.1", -1},
	}
	for _, tt := range tests {
		if got := Compare(MustParse(tt.a), MustParse(tt.b)); got != tt.want {
			t.Errorf("Compare(%s, %s) = %d; want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

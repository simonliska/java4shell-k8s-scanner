// Package rules describes a CPU-dependent JVM vulnerability: which CPU feature
// triggers it, which JDK versions are affected and which JVM flags mitigate it.
package rules

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/simonliska/java4shell-k8s-scanner/internal/javaver"
)

//go:embed java4shell.yaml
var builtinJava4Shell []byte

type Rule struct {
	ID          string     `json:"id"`
	CVE         string     `json:"cve"`
	Title       string     `json:"title"`
	References  []string   `json:"references,omitempty"`
	CPUFeature  CPUFeature `json:"cpuFeature"`
	Affected    []Range    `json:"affected"`
	Mitigations []Flag     `json:"mitigations"`
}

type CPUFeature struct {
	Name      string `json:"name"`      // e.g. avx512vbmi
	NodeLabel string `json:"nodeLabel"` // NFD label, "true" when the CPU has the feature
}

// Range covers versions with From <= v < Fixed, within one major version.
// An empty Fixed means no fixed release exists.
type Range struct {
	From  string `json:"from"`
	Fixed string `json:"fixed"`

	from, fixed javaver.Version
}

// Flag is a JVM flag value that disables the vulnerable code path:
// either an exact value (Equals) or a number below a limit (Below).
type Flag struct {
	Name   string `json:"name"`
	Equals string `json:"equals,omitempty"`
	Below  *int   `json:"below,omitempty"`
}

// Builtin returns the rules compiled into the binary.
func Builtin() ([]Rule, error) {
	r, err := Parse(builtinJava4Shell)
	if err != nil {
		return nil, fmt.Errorf("builtin java4shell rule: %w", err)
	}
	return []Rule{r}, nil
}

// LoadFile reads one rule from a YAML file.
func LoadFile(path string) (Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Rule{}, err
	}
	r, err := Parse(data)
	if err != nil {
		return Rule{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

func Parse(data []byte) (Rule, error) {
	var r Rule
	if err := yaml.UnmarshalStrict(data, &r); err != nil {
		return Rule{}, err
	}
	return r, r.validate()
}

func (r *Rule) validate() error {
	if r.ID == "" || r.CPUFeature.NodeLabel == "" || len(r.Affected) == 0 {
		return errors.New("id, cpuFeature.nodeLabel and affected are required")
	}
	for i := range r.Affected {
		a := &r.Affected[i]
		var err error
		if a.from, err = javaver.Parse(a.From); err != nil {
			return err
		}
		if a.Fixed != "" {
			if a.fixed, err = javaver.Parse(a.Fixed); err != nil {
				return err
			}
			if a.fixed.Major() != a.from.Major() || javaver.Compare(a.from, a.fixed) >= 0 {
				return fmt.Errorf("range %s..%s: fixed must be later in the same major version", a.From, a.Fixed)
			}
		}
	}
	for _, f := range r.Mitigations {
		if f.Name == "" || (f.Equals == "") == (f.Below == nil) {
			return fmt.Errorf("mitigation %q: needs a name and exactly one of equals/below", f.Name)
		}
	}
	return nil
}

// Affects reports whether JDK version v is in an affected range.
func (r Rule) Affects(v javaver.Version) bool {
	for _, a := range r.Affected {
		if v.Major() != a.from.Major() || javaver.Compare(v, a.from) < 0 {
			continue
		}
		if a.Fixed == "" || javaver.Compare(v, a.fixed) < 0 {
			return true
		}
	}
	return false
}

// MitigationInFlags checks effective JVM flag values (from -XX:+PrintFlagsFinal)
// and returns the mitigating one, e.g. "UseBASE64Intrinsics=false".
func (r Rule) MitigationInFlags(flags map[string]string) (string, bool) {
	for _, f := range r.Mitigations {
		if v, ok := flags[f.Name]; ok && f.mitigatedBy(v) {
			return f.Name + "=" + v, true
		}
	}
	return "", false
}

// MitigationInArgs looks for mitigating -XX options in JVM options text
// (command, args, JAVA_TOOL_OPTIONS...) and returns the option found.
// The last occurrence of a flag wins, like in the JVM.
func (r Rule) MitigationInArgs(args string) (string, bool) {
	for _, f := range r.Mitigations {
		opt, value, ok := f.lastInArgs(args)
		if ok && f.mitigatedBy(value) {
			return opt, true
		}
	}
	return "", false
}

func (f Flag) mitigatedBy(value string) bool {
	if f.Below != nil {
		n, err := strconv.Atoi(value)
		return err == nil && n < *f.Below
	}
	return value == f.Equals
}

// lastInArgs finds -XX:+Name, -XX:-Name or -XX:Name=value and returns the
// option text and its value ("true"/"false" for booleans).
func (f Flag) lastInArgs(args string) (opt, value string, ok bool) {
	re := regexp.MustCompile(`-XX:([+-]?)` + regexp.QuoteMeta(f.Name) + `(?:=(\S+))?(?:\s|$)`)
	matches := re.FindAllStringSubmatch(args, -1)
	if len(matches) == 0 {
		return "", "", false
	}
	m := matches[len(matches)-1]
	switch m[1] {
	case "+":
		value = "true"
	case "-":
		value = "false"
	default:
		value = m[2]
	}
	return strings.TrimSpace(m[0]), value, true
}

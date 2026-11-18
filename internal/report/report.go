// Package report prints scan results as a table or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/simonliska/java4shell-k8s-scanner/internal/scan"
)

type Report struct {
	Mode    string        `json:"mode"` // "read-only" or "exec"
	Results []scan.Result `json:"results"`
}

func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func Table(w io.Writer, r Report) {
	for _, res := range r.Results {
		feature := res.Rule.CPUFeature.Name
		fmt.Fprintf(w, "%s (%s)\n\n", res.Rule.ID, res.Rule.CVE)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "NAMESPACE\tPOD\tNODE\t%s\tJDK\tMITIGATION\tSTATUS\tNOTE\n", strings.ToUpper(feature))
		for _, f := range res.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				f.Namespace, f.Label(), or(f.Node, "<pending>"), cpu(f.CPU), or(f.JDK, "?"),
				or(f.Mitigation, "-"), f.Status, f.Note)
		}
		tw.Flush()

		if len(res.Findings) == 0 {
			fmt.Fprintln(w, "No Java containers found.")
		}
		fmt.Fprintf(w, "\nNodes: %s\n", nodeSummary(res.Nodes, feature))
		fmt.Fprintf(w, "Result: %s\n\n", statusSummary(res))
	}

	if r.Mode == "read-only" {
		fmt.Fprintln(w, "Read-only scan of pod specs and node labels. For exact JDK versions and runtime flags: kubectl java4shell --exec")
	}
}

func nodeSummary(nodes []scan.NodeInfo, feature string) string {
	count := map[scan.CPU]int{}
	for _, n := range nodes {
		count[n.CPU]++
	}
	s := fmt.Sprintf("%d total, %d with %s, %d without", len(nodes), count[scan.CPUYes], feature, count[scan.CPUNo])
	if count[scan.CPUUnknown] > 0 {
		s += fmt.Sprintf(", %d unknown (no Node Feature Discovery labels)", count[scan.CPUUnknown])
	}
	return s
}

func statusSummary(res scan.Result) string {
	var parts []string
	for _, s := range []scan.Status{scan.Exposed, scan.AtRisk, scan.Mitigated, scan.NotExposed, scan.NotAffected} {
		if n := res.Count(s); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "nothing to report"
	}
	return strings.Join(parts, ", ")
}

func cpu(c scan.CPU) string {
	if c == scan.CPUUnknown {
		return "?"
	}
	return string(c)
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

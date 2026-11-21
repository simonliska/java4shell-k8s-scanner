// kubectl-java4shell finds pods exposed to java4shell (CVE-2026-114938).
// Installed on PATH, it runs as `kubectl java4shell`.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // OIDC and other kubeconfig auth providers

	"github.com/simonliska/java4shell-k8s-scanner/internal/report"
	"github.com/simonliska/java4shell-k8s-scanner/internal/rules"
	"github.com/simonliska/java4shell-k8s-scanner/internal/scan"
)

// Set at build time: -ldflags "-X main.version=v0.1.0"
var version = "dev"

// errExposed makes the command exit with code 2, so CI can fail on it.
var errExposed = errors.New("exposed containers found")

type options struct {
	kube          *genericclioptions.ConfigFlags
	allNamespaces bool
	byPod         bool
	exec          bool
	output        string
	ruleFiles     []string
	concurrency   int
	timeout       time.Duration
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := newCommand().ExecuteContext(ctx)
	switch {
	case errors.Is(err, errExposed):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	o := &options{kube: genericclioptions.NewConfigFlags(true)}

	cmd := &cobra.Command{
		Use:   "java4shell",
		Short: "Find pods exposed to java4shell (CVE-2026-114938)",
		Long: `Find pods exposed to java4shell (CVE-2026-114938).

A container is EXPOSED only when all of these hold:
  1. its node's CPU has avx512vbmi (Node Feature Discovery label)
  2. it runs an affected JDK
  3. no mitigation flag is active (-XX:-UseBASE64Intrinsics or -XX:UseAVX=2)

AT RISK means it could become exposed, e.g. when rescheduled onto a VBMI node.

By default the scan is read-only: it reads node labels and pod specs.
--exec also runs "java -XX:+PrintFlagsFinal -version" in each running
container for the exact JDK version and the flags the JVM really uses.`,
		Example: `  kubectl java4shell                 # all namespaces, read-only
  kubectl java4shell -n payments     # one namespace
  kubectl java4shell --exec          # exact JDK version + runtime flags
  kubectl java4shell --pods          # one row per pod
  kubectl java4shell -o json         # machine-readable`,
		Version:       version,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Annotations:   map[string]string{cobra.CommandDisplayNameAnnotation: "kubectl java4shell"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	o.kube.AddFlags(cmd.Flags())
	cmd.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "scan all namespaces (the default unless -n is set)")
	cmd.Flags().BoolVar(&o.exec, "exec", false, "run java in each running container for exact JDK version and runtime flags (needs pods/exec)")
	cmd.Flags().BoolVar(&o.byPod, "pods", false, "one row per pod instead of per workload")
	cmd.Flags().StringVarP(&o.output, "output", "o", "table", "output format: table or json")
	cmd.Flags().StringSliceVar(&o.ruleFiles, "rules", nil, "rule YAML file(s) to use instead of the built-in java4shell rule")
	cmd.Flags().IntVar(&o.concurrency, "concurrency", 8, "parallel execs with --exec")
	cmd.Flags().DurationVar(&o.timeout, "exec-timeout", 30*time.Second, "timeout per exec with --exec")
	return cmd
}

func (o *options) run(cmd *cobra.Command) error {
	ctx := cmd.Context()
	if o.output != "table" && o.output != "json" {
		return fmt.Errorf("unknown output format %q (use table or json)", o.output)
	}

	ruleSet, err := o.loadRules()
	if err != nil {
		return err
	}

	config, err := o.kube.ToRESTConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	// All namespaces unless -n is given; -A wins, like in kubectl.
	namespace := ""
	if cmd.Flags().Changed("namespace") && !o.allNamespaces {
		namespace = *o.kube.Namespace
	}

	in := scan.Input{}
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsForbidden(err):
		fmt.Fprintln(os.Stderr, "Warning: no permission to list nodes; CPU features will be unknown.")
	case err != nil:
		return fmt.Errorf("listing nodes: %w", err)
	default:
		in.Nodes = nodes.Items
	}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}
	in.Pods = pods.Items

	mode := "read-only"
	if o.exec {
		mode = "exec"
		fmt.Fprintf(os.Stderr, "Probing running containers in %d pods...\n", len(in.Pods))
		in.Probes = scan.ProbeAll(ctx, &scan.KubeProber{Config: config, Client: client}, in.Pods, o.concurrency, o.timeout)
	}

	rep := report.Report{Mode: mode, ByPod: o.byPod}
	exposed := 0
	for _, rule := range ruleSet {
		res := scan.Analyze(rule, in)
		exposed += res.Count(scan.Exposed)
		rep.Results = append(rep.Results, res)
	}

	if o.output == "json" {
		if err := report.JSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else {
		report.Table(cmd.OutOrStdout(), rep)
	}

	if exposed > 0 {
		return errExposed
	}
	return nil
}

func (o *options) loadRules() ([]rules.Rule, error) {
	if len(o.ruleFiles) == 0 {
		return rules.Builtin()
	}
	var out []rules.Rule
	for _, path := range o.ruleFiles {
		r, err := rules.LoadFile(path)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

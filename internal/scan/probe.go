package scan

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ProbeCommand starts a short-lived JVM that inherits the container's env,
// so it sees the same JAVA_TOOL_OPTIONS as the app.
var ProbeCommand = []string{"java", "-Xmx32m", "-XX:+PrintFlagsFinal", "-version"}

// Probe is what --exec learned about one container.
type Probe struct {
	Version string            // from `java -version`, "" if not found
	Flags   map[string]string // effective JVM flags, e.g. UseBASE64Intrinsics=false
	Err     error             // exec failed (no java in the image, no permission, ...)
}

var versionLine = regexp.MustCompile(`version "([^"]+)"`)

// ParseProbe reads `java -XX:+PrintFlagsFinal -version`: flags on stdout,
// version on stderr.
func ParseProbe(stdout, stderr string) Probe {
	p := Probe{Flags: map[string]string{}}
	if m := versionLine.FindStringSubmatch(stderr + stdout); m != nil {
		p.Version = m[1]
	}
	// Flag lines look like: "     bool UseBASE64Intrinsics   = false   {product} {environment}"
	for _, line := range strings.Split(stdout, "\n") {
		if f := strings.Fields(line); len(f) >= 4 && f[2] == "=" {
			p.Flags[f[1]] = f[3]
		}
	}
	return p
}

type Prober interface {
	Probe(ctx context.Context, ref ContainerRef) Probe
}

// ProbeAll probes every running container, a few at a time.
func ProbeAll(ctx context.Context, p Prober, pods []corev1.Pod, concurrency int, timeout time.Duration) map[ContainerRef]Probe {
	var refs []ContainerRef
	for _, pod := range pods {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Running != nil {
				refs = append(refs, ContainerRef{pod.Namespace, pod.Name, cs.Name})
			}
		}
	}

	results := make(map[ContainerRef]Probe, len(refs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, max(concurrency, 1))
	for _, ref := range refs {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r := p.Probe(pctx, ref)
			mu.Lock()
			results[ref] = r
			mu.Unlock()
		})
	}
	wg.Wait()
	return results
}

// KubeProber runs ProbeCommand via the pods/exec API, like `kubectl exec`.
type KubeProber struct {
	Config *rest.Config
	Client kubernetes.Interface
}

func (k *KubeProber) Probe(ctx context.Context, ref ContainerRef) Probe {
	req := k.Client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ref.Namespace).Name(ref.Pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: ref.Container,
			Command:   ProbeCommand,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	// WebSocket first, SPDY for older API servers, like kubectl.
	ws, err := remotecommand.NewWebSocketExecutor(k.Config, "GET", req.URL().String())
	if err != nil {
		return Probe{Err: err}
	}
	spdy, err := remotecommand.NewSPDYExecutor(k.Config, "POST", req.URL())
	if err != nil {
		return Probe{Err: err}
	}
	exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return Probe{Err: err}
	}

	var stdout, stderr bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return Probe{Err: err}
	}
	return ParseProbe(stdout.String(), stderr.String())
}

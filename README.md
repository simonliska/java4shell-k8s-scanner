# kubectl java4shell

A kubectl plugin that finds the pods **actually exposed** to java4shell
([CVE-2026-114938](https://github.com/advisories/GHSA-6g7j-4xh3-xq2q)), not just
the ones that ship an affected JDK.

```console
$ kubectl java4shell
java4shell (CVE-2026-114938)

NAMESPACE  POD                   NODE            AVX512VBMI  JDK      MITIGATION                STATUS        NOTE
java-lab   vuln-b8b957858-8kqcf  k3s-server-t8i  yes         21.0.13  -                         EXPOSED
java-lab   vuln-b8b957858-c56zv  k3s-agent-t3    no          21.0.13  -                         AT RISK       can be scheduled on a node with avx512vbmi
java-lab   vuln-mitigated-...    k3s-server-t8i  yes         21.0.13  -XX:-UseBASE64Intrinsics  MITIGATED
java-lab   not-affected-...      k3s-server-t8i  yes         17.0.5   -                         NOT AFFECTED

Nodes: 2 total, 1 with avx512vbmi, 1 without
Result: 1 EXPOSED, 1 AT RISK, 1 MITIGATED, 1 NOT AFFECTED
```

## Why

java4shell is a heap overflow in the JVM's AVX-512 Base64 decoder. A container
is exposed only when **all three** are true:

1. the node's **CPU has `avx512vbmi`** (Intel Ice Lake+, AMD Zen 4+),
2. the container runs an **affected JDK**,
3. **no mitigation flag** is set.

Image scanners check only point 2, so they flag every Java 17+ image. This tool
checks all three. It also flags pods that would become exposed if rescheduled
onto a VBMI node (Karpenter, spot, mixed node pools).

## Install

With [krew](https://krew.sigs.k8s.io/), from this repo's own plugin index:

```bash
kubectl krew index add java4shell https://github.com/simonliska/java4shell-k8s-scanner.git
kubectl krew install java4shell/java4shell
```

Or with Go, or by downloading a binary from [Releases](https://github.com/simonliska/java4shell-k8s-scanner/releases):

```bash
go install github.com/simonliska/java4shell-k8s-scanner/cmd/kubectl-java4shell@latest
```

Any `kubectl-java4shell` binary on your `PATH` runs as `kubectl java4shell`.

**Requires** [Node Feature Discovery](https://kubernetes-sigs.github.io/node-feature-discovery/)
(NFD) in the cluster, which labels nodes with their CPU features. Without it,
node CPUs show as `?` and pods as AT RISK.

## Usage

```bash
kubectl java4shell                  # all namespaces, read-only
kubectl java4shell -n payments      # one namespace
kubectl java4shell --exec           # exact JDK version and runtime flags
kubectl java4shell -o json          # JSON output
kubectl java4shell --context prod   # standard kubectl flags work
```

Exit code `2` means at least one container is EXPOSED, so CI jobs can fail on it.

| | Default (read-only) | `--exec` |
|---|---|---|
| Reads | node labels, pod specs | + runs `java -XX:+PrintFlagsFinal -version` in each running container |
| JDK version | from JDK image tags like `eclipse-temurin:21.0.13_9-jdk` | exact, from the JVM |
| Mitigation | `-XX` flags in command, args and `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` / `_JAVA_OPTIONS` | + flags baked into the image |
| RBAC | `list` nodes and pods | + `create` on `pods/exec` |

The probe JVM uses at most 32 MB of heap. On clusters with tight memory limits,
start with one namespace.

## Statuses

| Status | Meaning | Action |
|---|---|---|
| **EXPOSED** | affected JDK, VBMI node, no mitigation | patch now or set the flag |
| **AT RISK** | could be rescheduled onto a VBMI node, or CPU / JDK version unknown | patch or set the flag; confirm with `--exec` |
| **MITIGATED** | affected JDK, mitigation flag active | upgrade when you can, then drop the flag |
| **NOT EXPOSED** | affected JDK, but no VBMI node can run the pod | patch in regular maintenance |
| **NOT AFFECTED** | JDK outside the affected ranges | nothing |

## How to fix

1. **Upgrade** to a fixed JDK (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 or your
   vendor's equivalent), rebuild the image and restart the pods.
2. **Until then**, turn off the vulnerable code path:

   ```yaml
   env:
     - name: JAVA_TOOL_OPTIONS
       value: "-XX:-UseBASE64Intrinsics"   # append if the variable already exists
   ```

   This only makes Base64 slower. `-XX:UseAVX=2` also works but disables all
   AVX-512 code.

## The vulnerability

| | |
|---|---|
| CVE | CVE-2026-114938 ("java4shell"), disclosed 2026-11-17 |
| Bug | heap overflow (CWE-122) in the AVX-512 VBMI Base64 decode intrinsic |
| Severity | CVSS 3.1 **8.1** |
| Affected | JDK 17.0.6+, 21, 25, 27 before the fixed builds; EOL releases 18–20, 22–24, 26 |
| Fixed | 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 |
| Not affected | JDK 8, 11, 17.0.0–17.0.5; ARM64; x86 CPUs without VBMI |

Sources:

- Versions and severity: [OpenJDK advisory 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17),
  [Oracle CPU](https://www.oracle.com/security-alerts/cspunov2026.html),
  [GHSA-6g7j-4xh3-xq2q](https://github.com/advisories/GHSA-6g7j-4xh3-xq2q).
  Fixed version numbers: [adoptium/temurin#326](https://github.com/adoptium/temurin/issues/326).
- Lower bound 17.0.6: the intrinsic ([JDK-8268276](https://github.com/openjdk/jdk17u/commit/07050b000ce2))
  first appears in tag `jdk-17.0.6-ga`.
- EOL releases: they contain the intrinsic and never get a fix, so they count as affected.
- CPU condition and flags: researcher write-ups, confirmed in the [lab](#lab).

All of this lives in one rule file: [`internal/rules/java4shell.yaml`](internal/rules/java4shell.yaml).

## Limitations

- **Distro JDKs** (Red Hat, Ubuntu) may backport the fix without changing the
  version, so they show as affected. Check your vendor's advisory.
- **Read-only mode guesses** which containers run Java from image names and env
  vars. Use `--exec` to catch the rest.
- **`--exec` needs `java` on `PATH`.** Custom runtime paths (e.g. jlink images)
  fall back to read-only results.
- **Flags added by start scripts** (e.g. from `JAVA_OPTS`) are not visible, so
  such pods show as EXPOSED instead of MITIGATED.
- **NFD label filters:** if NFD is configured to skip the `AVX512VBMI` label, a
  VBMI node shows as `no`. The default NFD config labels it.
- Oracle's 8u511b33-perf build is affected but not detected (not OpenJDK).

## Lab

A 2-node k3s cluster on AWS, built with Terraform (about $0.065/h):

| Instance | CPU | `avx512vbmi` | Result |
|---|---|---|---|
| t8i.small | Intel Xeon 6975P-C (Granite Rapids) | yes | EXPOSED / MITIGATED |
| t3.small | Intel Xeon Platinum 8259CL (Cascade Lake) | no | AT RISK / NOT EXPOSED |

The t3 has AVX-512 but not VBMI, so checking the AVX level alone is not enough.

```bash
scripts/up.sh                 # create the cluster
scripts/check-vbmi.sh         # compare /proc/cpuinfo with the NFD label
scripts/deploy-test-apps.sh   # vulnerable, mitigated and not-affected pods
kubectl java4shell --exec
scripts/down.sh               # destroy everything
```

The test pods run an idle JVM. Nothing here triggers the bug.

## Development

```bash
go test ./...
go build -o bin/kubectl-java4shell ./cmd/kubectl-java4shell
```

The logic in [`internal/scan`](internal/scan) works on plain Kubernetes
objects, so tests need no cluster.

Release (needs [GoReleaser](https://goreleaser.com/) and a logged-in `gh` CLI):

```bash
git tag v0.1.0 && git push --tags
GITHUB_TOKEN=$(gh auth token) goreleaser release --clean
mkdir -p plugins && scripts/krew-manifest.sh v0.1.0 > plugins/java4shell.yaml
git add plugins && git commit -m "krew: v0.1.0" && git push
```

## Scope

Defensive only: detection and mitigation, no exploit code. Scan only clusters
you are allowed to inspect.

## License

Copyright 2026 Simon Liska. [Apache License 2.0](LICENSE).

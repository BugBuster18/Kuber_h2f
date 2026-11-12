# Benchmark: public attack paths

The clusters in `demo/clusters/` were written by us. This folder is the opposite: **manifests and attack paths written by other people**, used to check our tool against an outside answer key.

| Folder | Source | Licence | Upstream version |
|---|---|---|---|
| `goat/` | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) by Madhu Akula, the files its `setup-kubernetes-goat.sh` applies | MIT (`goat/LICENSE`) | `master` @ 723a0db (2026-04-16) |
| `badpods/` | [Bad Pods](https://github.com/BishopFox/badPods) by Bishop Fox, the eight `*-exec-pod.yaml` manifests | MIT (`badpods/LICENSE`) | `main` @ 107e5d8 (2025-12-30) |
| `expected.yaml` | The answer key: each attack path as documented by those projects, with a link to the page | — | — |

The manifests are copied **unmodified**, with two exceptions:

* `goat/metadata-db.yaml`: upstream installs it with Helm. It is the chart rendered by hand with its default values.
* The Bad Pods have no namespace, so they are applied with `-n badpods`.

## Two sets: live demo vs full result

| Set | What is deployed | Graph | Used for |
|---|---|---|---|
| **Live demo** (default) | Goat: system-monitor, hunger-check, internal-proxy · Bad Pods: privileged, hostPID | 12 nodes, 21 edges | showing it live: small enough to explain on screen |
| **Full** (`BENCH_FULL=1`) | all of Kubernetes Goat + all 8 Bad Pods | 26 nodes, 177 edges | the reported numbers (`results-full.json`) |

The live-demo set has no hostPath pod, which is the one case ML gets wrong. Report the **full** numbers, so that mistake stays visible.

### Full result (`results-full.json`, with Trivy image scanning)

| | Old weights | ML weights |
|---|---|---|
| Goat paths found | 7/7 | 7/7 |
| Goat mean rank of documented paths (of 80) | 17.5 | **2.5** |
| Bad Pods correct verdicts | 5/8 | **7/8** (misses hostPath) |
| Real escapes ranked above non-escapes | 62% | **91%** |

## Run it

```bash
./demo/present.sh          # pick kav-bench, then option 5
# or directly:
./demo/setup.sh bench                                    # create kind-kav-bench, live-demo set (once)
BENCH_FULL=1 ./demo/setup.sh bench                       # ...or the full set
python main.py --scan-images benchmark -c kind-kav-bench # compare
```

Results are saved to `data/benchmark/latest.json`.

## What is measured

* **Kubernetes Goat:** 7 scenarios whose attack follows from cluster configuration (2, 3, 4, 8, 11, 12, 16). For each one:
  * **found:** does our graph contain the documented path?
  * **rank:** where does it rank among all attack paths in the cluster, under the old weights and under the ML weights?
* **Bad Pods:** for each of the 8 pods, can its own spec reach the node? This is compared with what the Bad Pods README says.
  * Old weights have no probability, so any modelled pod → node step counts as a claimed escape.
  * ML weights claim an escape when P ≥ 50%.

## Safety

These are deliberately vulnerable workloads (privileged pods, host mounts, a web terminal in `system-monitor`). Keep them on the local kind cluster:

* Do not port-forward them to `0.0.0.0`.
* Delete the cluster when you are done: `kind delete cluster --name kav-bench`.

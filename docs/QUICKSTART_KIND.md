# VibeSafe Quick Start with Kind

Get VibeSafe running on a local Kubernetes cluster using [Kind](https://kind.sigs.k8s.io/) in under 5 minutes.

## Prerequisites

- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) installed
- [Docker](https://docs.docker.com/get-docker/) or [Podman](https://podman.io/) (Kind uses one of these)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (optional, for verification)

## 1. Create a Kind cluster

```bash
kind create cluster --name vibesafe-demo
```

Expected output: `Created cluster "vibesafe-demo"`

## 2. Verify the cluster

```bash
kubectl cluster-info --context kind-vibesafe-demo
kubectl get nodes
```

## 3. Install VibeSafe

```bash
cd /path/to/VibeSafe
pip install -e .
```

## 4. Deploy your first vibe

Use `--no-spire` because Kind doesn't have SPIRE installed by default:

```bash
vibe deploy tests/sample_vibe_code.py --project my-ai-agent --no-spire
```

You'll see:
- Security analysis findings (network, high-risk modules)
- Vulnerability scan (pip-audit + roxctl for container)
- Manifests applied to the cluster

## 5. Verify the deployment

```bash
# Check pod status (may take 1–2 min on first run to pull image + pip install)
kubectl get pods -n default

# View logs once Running
kubectl logs my-ai-agent-vibe -n default -f
```

## 6. Dry run (no cluster needed)

Generate manifests without applying:

```bash
vibe deploy tests/sample_vibe_code.py --project my-ai-agent --dry-run
```

Manifests are written to `.vibe-build/`.

## 7. Cleanup

```bash
# Delete the cluster
kind delete cluster --name vibesafe-demo
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Pod stuck in `ContainerCreating` | You forgot `--no-spire`; use `--no-spire` for Kind |
| Pod in `Error` / `CrashLoopBackOff` | Check logs: `kubectl logs my-ai-agent-vibe -n default --previous` |
| `Connection refused` during deploy | Kind cluster not running; run `kind create cluster` |
| Slow first deploy | UBI image pull + pip install takes 1–2 minutes |

## Next steps

- **Add RHACS:** See [RHACS_KIND.md](RHACS_KIND.md) to deploy Red Hat Advanced Cluster Security on Kind
- **Add SPIRE:** See [SPIRE_SETUP.md](SPIRE_SETUP.md) to install SPIRE on Kind
- **Vulnerability scanning:** roxctl (RHACS); see [RHACS_KIND.md](RHACS_KIND.md)
- **Your own script:** Replace `tests/sample_vibe_code.py` with your Python file

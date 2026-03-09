# SPIRE Setup for VibeSafe

This guide walks through setting up SPIRE so your vibe-deployed workloads can obtain SPIFFE identities.

## Architecture

VibeSafe mounts the SPIRE CSI volume at `/run/spire/sockets` in your pod. Your code uses the **SPIFFE Workload API** to fetch X.509 SVIDs (certificates) or JWT tokens for mTLS or authentication.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  SPIRE Server   │────▶│  SPIRE Agent     │────▶│  Your Pod       │
│  (identity DB)  │     │  (DaemonSet)     │     │  vibe_code.py   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                          │
                               │   CSI volume mounts       │
                               │   Workload API socket     │
                               └──────────────────────────┘
```

---

## 1. Install SPIRE on Kubernetes

### Option A: Helm (recommended)

**Important:** CRDs must be installed first, then the main chart.

```bash
# Add the SPIRE Helm repo
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update

# Step 1: Install CRDs first (required)
helm upgrade --install spire-crds spire-crds \
  -n spire \
  --create-namespace \
  --repo https://spiffe.github.io/helm-charts-hardened/

# Step 2: Install SPIRE (server + agent + CSI driver)
# Note: Use chart name "spire" with --repo (not "spiffe/spire")
helm upgrade --install spire spire \
  -n spire \
  --repo https://spiffe.github.io/helm-charts-hardened/

# Verify
kubectl get pods -n spire
```

### Option B: Kind-specific (with Node attestation)

For Kind, you may need to configure the agent for `k8s_psat` (Kubernetes Node) attestation. See the [SPIRE Kubernetes Quickstart](https://spiffe.io/docs/latest/try/getting-started-k8s/).

---

## 2. Register Your Vibe Workload

SPIRE must know which pods get which SPIFFE IDs. Register an entry for your vibe deployment.

**Create a registration entry** (adjust namespace/labels to match your deployment):

```bash
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry create \
  -spiffeID "spiffe://example.org/workload/my-ai-agent" \
  -parentID "spiffe://example.org/ns/default/sa/default" \
  -selector "k8s:ns:default" \
  -selector "k8s:pod-name:my-ai-agent-vibe"
```

Or use **Kubernetes Workload Registrar** (auto-registration by label):

```yaml
# spire-registrar-config.yaml
cluster: "kind-ai-security-demo"   # Your cluster name
trust_domain: "example.org"
pod_controller: true
```

---

## 3. Use SPIRE in Your Python Code

Install the SPIFFE Python client:

```bash
pip install spiffe
```

### Fetch X.509 SVID (for mTLS)

```python
from spiffe import WorkloadApiClient

# Socket path matches VibeSafe's CSI mount
with WorkloadApiClient("unix:///run/spire/sockets/workload_api.sock") as client:
    x509_svid = client.fetch_x509_svid()
    print(f"My SPIFFE ID: {x509_svid.spiffe_id}")
    # Use x509_svid.cert_chain, x509_svid.private_key for mTLS
```

### Fetch JWT SVID

```python
from spiffe import WorkloadApiClient

with WorkloadApiClient("unix:///run/spire/sockets/workload_api.sock") as client:
    jwt_svid = client.fetch_jwt_svid(audience={"my-service"})
    print(f"JWT: {jwt_svid.token}")
```

### Auto-renewing SVID (recommended for long-running services)

```python
from spiffe import X509Source

# Automatically fetches and renews SVID
with X509Source("unix:///run/spire/sockets/workload_api.sock") as source:
    svid = source.get_svid()
    print(f"SPIFFE ID: {svid.spiffe_id}")
```

### Environment Variable (optional)

SPIRE clients often read the socket from env. Set in your pod if needed:

```yaml
env:
  - name: SPIFFE_ENDPOINT_SOCKET
    value: "unix:///run/spire/sockets/workload_api.sock"
```

Then use:

```python
from spiffe import WorkloadApiClient

# Uses SPIFFE_ENDPOINT_SOCKET if not specified
with WorkloadApiClient() as client:
    x509_svid = client.fetch_x509_svid()
```

---

## 4. Deploy Without `--no-spire`

Once SPIRE is installed and the workload is registered:

```bash
vibe deploy my_script.py --project my-ai-agent
# Do NOT use --no-spire
```

The pod will get the SPIRE CSI volume and your code can use the Workload API.

---

## 5. Trust Domain Alignment

VibeSafe uses `spiffe://example.org/workload/<project_name>` by default. Update the pod template or your registration to match your trust domain.

| Component   | Trust domain example     |
|------------|---------------------------|
| VibeSafe   | `spiffe://example.org/...` |
| Your SPIRE | Configure in server config |

---

## 6. Troubleshooting

| Problem | Check |
|--------|-------|
| Pod stuck in `ContainerCreating` | SPIRE CSI driver not installed; use `--no-spire` for local dev |
| "connection refused" in code | Agent not running; `kubectl get pods -n spire` |
| "no identity" / empty SVID | Workload not registered; create entry for your pod/namespace |
| Wrong socket path | CSI mounts at `/run/spire/sockets`; socket may be `workload_api.sock` or in a subdir |

Check socket contents:

```bash
kubectl exec my-ai-agent-vibe -n default -- ls -la /run/spire/sockets/
```

---

## References

- [SPIRE Documentation](https://spiffe.io/docs/latest/)
- [Kubernetes Quickstart](https://spiffe.io/docs/latest/try/getting-started-k8s/)
- [py-spiffe (Python client)](https://github.com/HewlettPackard/py-spiffe)
- [SPIRE Helm Charts](https://github.com/spiffe/helm-charts-hardened)

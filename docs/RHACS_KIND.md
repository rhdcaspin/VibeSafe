# RHACS with Kind Cluster

This guide shows how to use [Red Hat Advanced Cluster Security for Kubernetes](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) (RHACS) with a Kind cluster. Choose one of two scenarios:

| Scenario | When to use |
|----------|-------------|
| **RHACS Cloud Service** | Connect your Kind cluster to an existing hosted Central (e.g. `staging.demo.stackrox.com`). No Central installation required. |
| **Self-hosted Central** | Run Central and all components on Kind. Full local stack. |

---

## Prerequisites

- Kind cluster running
- [Helm](https://helm.sh/docs/intro/install/) 3.x
- **Red Hat account** with RHACS entitlement (trial or subscription)
- Sufficient resources: Central needs ~4 CPU, 8Gi RAM; ensure Kind has capacity

---

## Scenario A: Connect to RHACS Cloud Service

Use this when Central is hosted (e.g. Red Hat Hybrid Cloud Console, `staging.demo.stackrox.com`).

### 1. Add Helm repository

```bash
helm repo add rhacs https://mirror.openshift.com/pub/rhacs/charts/
helm repo update
```

### 2. Create pull secret

RHACS images from `registry.redhat.io` require authentication.

```bash
kubectl create namespace stackrox

kubectl create secret docker-registry rhacs-pull-secret \
  --docker-server=registry.redhat.io \
  --docker-username="YOUR_REDHAT_USERNAME" \
  --docker-password="YOUR_REDHAT_PASSWORD" \
  --docker-email="your-email@example.com" \
  -n stackrox
```

**Alternative:** Use a [Registry Service Account](https://access.redhat.com/RegistryAuthentication).

### 3. Generate cluster registration secret (CRS)

Create a CRS from your Central instance using `roxctl`:

```bash
export ROX_CENTRAL_ADDRESS=staging.demo.stackrox.com:443
export ROX_API_TOKEN=<admin_api_token>

roxctl -e "$ROX_CENTRAL_ADDRESS" central crs generate dc-kind-cluster \
  --output dc-kind-cluster-cluster-registration-secret.yaml
```

- **ROX_CENTRAL_ADDRESS:** Your Central API endpoint (without `https://`). Get it from the RHACS UI or Hybrid Cloud Console.
- **ROX_API_TOKEN:** Create in the RHACS UI under **Platform Configuration** → **Integrations** → **API Tokens**.

Store the CRS file securely; it contains secrets. Add `*.yaml` patterns for CRS files to `.gitignore` if needed.

### 4. Remove any existing CRS secret (if re-installing)

If you previously applied the CRS with `kubectl`, delete it so Helm can manage it:

```bash
kubectl delete secret cluster-registration-secret -n stackrox
```

### 5. Install secured cluster services

Pass the CRS to Helm via `--set-file`. Do **not** apply the CRS with `kubectl`; Helm reads it directly.

```bash
helm install -n stackrox --create-namespace stackrox-secured-cluster-services rhacs/secured-cluster-services \
  --set-file crs.file=dc-kind-cluster-cluster-registration-secret.yaml \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set clusterName=kind-cluster \
  --set centralEndpoint=staging.demo.stackrox.com:443
```

- **crs.file:** Path to your CRS YAML file.
- **clusterName:** Name shown in the RHACS UI (e.g. `kind-cluster` or your CRS name).
- **centralEndpoint:** Central API endpoint (host:port). Use `wss://host:443` if behind a non-gRPC load balancer.

### 6. Verify

```bash
kubectl -n stackrox get pods
```

You should see `collector-*`, `sensor-*`, and `admission-control-*` pods. In the RHACS UI, go to **Platform Configuration** → **Clusters** to confirm your Kind cluster appears.

### 7. VibeSafe image scanning with roxctl

With `ROX_CENTRAL_ADDRESS` and `ROX_API_TOKEN` set, VibeSafe uses roxctl for container vulnerability scanning:

```bash
export ROX_CENTRAL_ADDRESS=staging.demo.stackrox.com:443
export ROX_API_TOKEN=<your_token>

vibe scan script.py                    # Pip + container scan
vibe deploy script.py --project demo   # Scan runs during deploy
```

---

## Scenario B: Self-hosted Central on Kind

Use this to run Central and the secured cluster entirely on Kind.

### 1. Add Helm repository and pull secret

Same as Scenario A (steps 1–2 above).

### 2. Install Central

```bash
kubectl create namespace stackrox --dry-run=client -o yaml | kubectl apply -f -

helm install -n stackrox --create-namespace stackrox-central-services rhacs/central-services \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set central.exposure.loadBalancer.enabled=false
```

Wait for Central to be ready (5–10 minutes):

```bash
kubectl -n stackrox get pods -w
```

Look for `central-*` and `scanner-*` pods in `Running` state.

### 3. Get admin password and access Central

```bash
# Get initial admin password
kubectl -n stackrox get secret central-htpasswd -o jsonpath='{.data.password}' | base64 -d
echo

# Port-forward for browser access
kubectl -n stackrox port-forward svc/central 8443:8443
```

Open `https://localhost:8443`, accept the self-signed cert, and log in with `admin` and the password above.

### 4. Generate credentials for the secured cluster

Choose one:

**Option A – Cluster registration secret (CRS)**

```bash
export ROX_CENTRAL_ADDRESS=localhost:8443
export ROX_API_TOKEN=<admin_api_token>

roxctl -e "$ROX_CENTRAL_ADDRESS" --insecure central crs generate dc-kind-cluster \
  --output dc-kind-cluster-cluster-registration-secret.yaml
```

Use `--insecure` when Central uses a self-signed cert.

**Option B – Init bundle from Central UI**

1. In RHACS: **Platform Configuration** → **Integrations** → **Cluster init bundles**
2. **Generate bundle** → name it (e.g. `kind-init-bundle`) → **Generate**
3. Download the Helm values file or YAML

### 5. Install secured cluster services

**With CRS:**

```bash
# Remove existing secret if you previously applied it manually
kubectl delete secret cluster-registration-secret -n stackrox 2>/dev/null || true

helm install -n stackrox stackrox-secured-cluster-services rhacs/secured-cluster-services \
  --set-file crs.file=dc-kind-cluster-cluster-registration-secret.yaml \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set clusterName=kind-cluster \
  --set centralEndpoint=central.stackrox.svc:443
```

**With init bundle (values file from portal):**

```bash
helm install -n stackrox stackrox-secured-cluster-services rhacs/secured-cluster-services \
  -f values-from-portal.yaml \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set clusterName=kind-cluster
```

**With init bundle (YAML only):**

```bash
kubectl create -f init-bundle.yaml -n stackrox

helm install -n stackrox stackrox-secured-cluster-services rhacs/secured-cluster-services \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set clusterName=kind-cluster \
  --set centralEndpoint=central.stackrox.svc:443
```

### 6. Verify

```bash
kubectl -n stackrox get pods
```

In RHACS UI: **Platform Configuration** → **Clusters** → your Kind cluster should appear within a few minutes.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `A CA certificate must be specified` | When using a CRS, pass it to Helm with `--set-file crs.file=<path>`. Do not rely on `kubectl apply` alone. |
| `Secret "cluster-registration-secret" exists... invalid ownership metadata` | Delete the existing secret: `kubectl delete secret cluster-registration-secret -n stackrox`, then run `helm install` again. Helm will create it. |
| `ImagePullBackOff` on RHACS pods | Ensure `rhacs-pull-secret` exists and credentials are valid for `registry.redhat.io`. |
| Central not ready after 15 min | Check `kubectl describe pod -n stackrox -l app=central`. Central needs PVC; Kind uses `local-path` by default. |
| Secured cluster not appearing in UI | Check Sensor logs: `kubectl logs -n stackrox -l app=sensor -f`. Verify `centralEndpoint` and CRS/init bundle. |
| Insufficient resources | Create Kind with more nodes; see [Resource considerations](#resource-considerations-for-kind) below. |

---

## Resource considerations for Kind

RHACS is resource-intensive. Use a larger Kind cluster for a smoother experience:

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
```

```bash
kind create cluster --name rhacs-demo --config kind-config.yaml
```

---

## References

- [RHACS Installation (Red Hat Docs)](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/)
- [RHACS Cloud Service – Setting up secured clusters](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/rhacs_cloud_service/setting-up-rhacs-cloud-service-with-kubernetes-secured-clusters)
- [Red Hat Container Registry Authentication](https://access.redhat.com/RegistryAuthentication)

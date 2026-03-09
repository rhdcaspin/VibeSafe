# Deploy RHACS on Kind

This guide walks through deploying [Red Hat Advanced Cluster Security for Kubernetes](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) (RHACS) on a Kind cluster.

## Prerequisites

- Kind cluster running
- [Helm](https://helm.sh/docs/intro/install/) 3.x
- **Red Hat account** with RHACS entitlement (trial or subscription)
- Sufficient resources: RHACS Central needs ~4 CPU, 8Gi RAM; ensure your Kind cluster has capacity

## 1. Create Red Hat registry pull secret

RHACS images are hosted on `registry.redhat.io` and require authentication.

```bash
# Log in to Red Hat Container Registry
podman login registry.redhat.io
# Or: docker login registry.redhat.io

# Create pull secret in the stackrox namespace (create NS first)
kubectl create namespace stackrox

kubectl create secret docker-registry rhacs-pull-secret \
  --docker-server=registry.redhat.io \
  --docker-username="YOUR_REDHAT_USERNAME" \
  --docker-password="YOUR_REDHAT_PASSWORD" \
  --docker-email="your-email@example.com" \
  -n stackrox
```

**Alternative:** Use a [Registry Service Account](https://access.redhat.com/RegistryAuthentication) (recommended for automation).

## 2. Add RHACS Helm repository

```bash
helm repo add rhacs https://mirror.openshift.com/pub/rhacs/charts/
helm repo update
```

## 3. Install Central

Central provides the RHACS UI, API, and Scanner. Deploy it first.

```bash
helm install -n stackrox stackrox-central-services rhacs/central-services \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set central.exposure.loadBalancer.enabled=false
```

Wait for Central to be ready (5–10 minutes):

```bash
kubectl -n stackrox get pods -w
```

Look for `central-*` and `scanner-*` pods in `Running` state.

## 4. Get the admin password and expose Central

```bash
# Get the initial admin password
kubectl -n stackrox get secret central-htpasswd -o jsonpath='{.data.password}' | base64 -d
echo
```

Expose Central for browser access. For Kind, use port-forward:

```bash
# Port-forward Central (run in background or separate terminal)
kubectl -n stackrox port-forward svc/central 8443:8443
```

Open `https://localhost:8443` in your browser (accept the self-signed cert). Log in with username `admin` and the password from above.

## 5. Generate init bundle

The Secured Cluster needs an init bundle to authenticate with Central.

1. In the RHACS UI: **Platform Configuration** → **Integrations** → **Cluster init bundles**
2. Click **Generate bundle**
3. Name it (e.g. `kind-init-bundle`) → **Generate**
4. **Download the Helm values file** (recommended) or the YAML init bundle
5. If you downloaded the YAML: apply it with `kubectl create -f init-bundle.yaml -n stackrox`
6. If you downloaded the Helm values file: use it in the next step with `-f values-from-portal.yaml`

## 6. Install Secured Cluster

This deploys the Sensor, Admission Controller, and Collector on your Kind cluster.

**Option A – Using the Helm values file from the portal (recommended):**

```bash
# Use the file you downloaded from the RHACS UI (includes init bundle ref)
helm install -n stackrox stackrox-secured-cluster-services rhacs/secured-cluster-services \
  -f values-from-portal.yaml \
  --set imagePullSecrets.useExisting=rhacs-pull-secret \
  --set clusterName=kind-vibesafe-demo
```

**Option B – Manual values (after applying init bundle YAML):**

```bash
helm install -n stackrox stackrox-secured-cluster-services rhacs/secured-cluster-services \
  -f - <<EOF
clusterName: kind-vibesafe-demo
imagePullSecrets:
  useExisting: rhacs-pull-secret
centralEndpoint: central.stackrox.svc:443
EOF
```

**Note:** Set `clusterName` to match your Kind cluster. Check with `kubectl config current-context` (e.g. `kind-vibesafe-demo`).

Verify:

```bash
kubectl -n stackrox get pods
```

You should see `collector-*`, `sensor-*`, and `admission-control-*` pods.

## 7. Verify the cluster in RHACS

1. In the RHACS UI, go to **Platform Configuration** → **Clusters**
2. Your Kind cluster should appear within a few minutes
3. Navigate to **Dashboard** to see vulnerabilities, compliance, and risk

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ImagePullBackOff` on RHACS pods | Check pull secret; ensure `rhacs-pull-secret` exists and credentials are valid |
| Central not ready after 15 min | Check `kubectl describe pod -n stackrox -l app=central`; Central needs PVC – Kind uses local-path by default |
| Secured cluster not appearing | Ensure init bundle was applied; check Sensor logs: `kubectl logs -n stackrox -l app=sensor -f` |
| Insufficient resources | Create Kind cluster with more nodes/resources: `kind create cluster --config kind-config.yaml` |

## Resource considerations for Kind

RHACS is resource-intensive. For a smoother experience, create Kind with more capacity:

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
- [Installing on other platforms](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.6/html/installing/installing-rhacs-on-other-platforms)
- [Red Hat Registry Authentication](https://access.redhat.com/RegistryAuthentication)

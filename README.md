<p align="center">
  <img src="assets/logo.svg" alt="VibeSafe" width="96" height="96" />
</p>

<h1 align="center">VibeSafe</h1>

<p align="center">
  <strong>Deploy Python vibe code to Kubernetes with zero-trust security in one command.</strong>
</p>

<p align="center">
  Analyzes your code, detects required permissions, and generates secure K8s manifests with SELinux, Validating Admission Policies, Network Policies, and SPIRE workload identities — plus built-in vulnerability scanning.
</p>

---

## Quick Start (Kind)

```bash
kind create cluster --name vibesafe-demo
pip install -e .
vibe deploy tests/sample_vibe_code.py --project my-ai-agent --no-spire
```

See [docs/QUICKSTART_KIND.md](docs/QUICKSTART_KIND.md) for the full guide.

## Installation

```bash
pip install -e .
```

## Usage

```bash
vibe deploy sample_vibe_code.py --project my-ai-agent --dry-run
```

## Vulnerability Scanning

VibeSafe scans for known vulnerabilities before deploy:

- **Python packages** (pip-audit) – CVEs in dependencies like `requests`
- **Container image** (Trivy) – CVEs in the UBI base image

**Standalone scan:**
```bash
vibe scan script.py                    # Scan deps + container
vibe scan script.py --no-container     # Pip packages only
vibe scan script.py --image myimg:tag  # Custom image
vibe scan script.py --strict           # Exit 1 if vulns found
```

**During deploy:** Scanning runs by default. Use `--no-scan` to skip.

## SPIRE / Workload Identity

For production deployments with SPIFFE identities, omit `--no-spire`. See [docs/SPIRE_SETUP.md](docs/SPIRE_SETUP.md) for installation and usage in your Python code.

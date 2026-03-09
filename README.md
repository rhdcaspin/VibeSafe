# VibeSafe

Deploy Python vibe code to Kubernetes with zero-trust security (SELinux, VAP, SPIRE, Network Policies) and vulnerability scanning.

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

<p align="center">
  <img src="assets/logo.svg" alt="VibeSafe" width="96" height="96" />
</p>

<h1 align="center">VibeSafe</h1>

<p align="center">
  <strong>Deploy Python vibe code to Kubernetes with zero-trust security in one command.</strong>
</p>

<p align="center">
  VibeSafe is an enterprise-grade Kubernetes control plane designed to safely execute rapidly generated AI code ("vibe code"). It bridges the gap between the speed of AI development and the strict compliance requirements of sovereign, air-gapped, and highly regulated cloud environments.

With a single command (vibe deploy), VibeSafe analyzes Python code intent and dynamically wraps the workload in a mathematically isolated, zero-trust sandbox.

✨ Key Features
Identity-First Security (SPIRE): Eliminates static secrets. Every deployment is dynamically issued a short-lived, cryptographically verifiable identity (SVID) scoped exactly to its needs.

Native Guardrails (VAP): Uses Kubernetes Validating Admission Policies (CEL) to strictly enforce non-privileged execution and required security contexts without relying on third-party webhooks.

Hardware-Grade Isolation: Automatically injects precise SELinux profiles (e.g., container_t) and Default-Deny Network Policies to prevent lateral movement and unauthorized egress.

Sovereign-Cloud Ready: Built for enterprise air-gapped environments. No external API dependencies, no "phone home" telemetry—just pure, self-hosted execution control.

🚀 The "One-Command" Experience
Bash
$ vibe deploy ./ai_agent.py --secure
🔍 Analyzing script profile...
🛡️ Generating Zero-Trust manifests (SELinux, VAP, SPIRE)...
✅ Workload isolated and deployed securely to cluster.
</p>

---

## Quick Start (Kind)

```bash
kind create cluster --name vibesafe-demo
pip install -e .
vibe deploy tests/sample_vibe_code.py --project my-ai-agent --no-spire
```

See [docs/QUICKSTART_KIND.md](docs/QUICKSTART_KIND.md) for the full guide.

To connect VibeSafe deployments to RHACS for vulnerability and compliance monitoring, see [docs/RHACS_KIND.md](docs/RHACS_KIND.md).

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
- **Container image** (roxctl/RHACS) – CVEs in the base image via RHACS Central

**Standalone scan:**
```bash
vibe scan script.py                    # Scan deps + container
vibe scan script.py --no-container     # Pip packages only
vibe scan script.py --image myimg:tag  # Custom image
vibe scan script.py --strict           # Exit 1 if vulns found
vibe scan script.py --csv report.csv   # Export results to CSV
```

**During deploy:** Scanning runs by default. Use `--no-scan` to skip.

**CSV export:** Use `--csv path.csv` to write findings. **CRITICAL** vulns stop the process (exit 1).

**Container scanning:** Uses roxctl. Set `ROX_CENTRAL_ADDRESS` and `ROX_API_TOKEN`. See [docs/RHACS_KIND.md](docs/RHACS_KIND.md).

## SPIRE / Workload Identity

For production deployments with SPIFFE identities, omit `--no-spire`. See [docs/SPIRE_SETUP.md](docs/SPIRE_SETUP.md) for installation and usage in your Python code.

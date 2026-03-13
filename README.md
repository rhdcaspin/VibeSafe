<p align="center">
  <img src="assets/logo.svg" alt="VibeSafe" width="96" height="96" />
</p>

<h1 align="center">VibeSafe</h1>

<p align="center">
  <strong>A CLI that deploys Python scripts to Kubernetes with security policies derived from code analysis.</strong>
</p>

VibeSafe analyzes Python code and generates Kubernetes manifests to run it in a constrained environment. It:

- **Static analysis**: Parses imports (e.g. `requests`, `urllib`) and extracts URLs/hosts to infer network needs
- **Container build**: Builds a UBI-based image with your code and detected pip dependencies, or uses ConfigMap-based deploy
- **Manifest generation**: Produces Pod, NetworkPolicy, ValidatingAdmissionPolicy, and optionally SPIRE volume manifests
- **Security defaults**: Sets `container_t` SELinux type, default-deny network policy with egress limited to extracted hosts/ports
- **Vulnerability scanning**: Runs pip-audit on dependencies and roxctl for container image CVE checks before deploy

Optional SPIRE integration provides workload identity (SVID) when a SPIRE server is configured in the cluster.

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
# Single script
vibe deploy sample_vibe_code.py --project my-ai-agent --dry-run

# Directory (packages all .py files)
vibe deploy src/myapp/ --project my-app --main myapp/main.py

# Multiple scripts
vibe deploy script1.py script2.py utils.py --project my-app --main script1.py
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

## Future Plans

Planned improvements include: broader base image support (Alpine, Distroless), support for `requirements.txt` and lockfiles instead of AST-inferred pip packages, richer AST analysis for environment variables and secrets usage, optional policy-as-code export (OPA/Rego), and improved offline/air-gapped build flows. Integration with additional scanners (Grype, Trivy) alongside roxctl is under consideration.

## Community

We welcome bug reports, documentation improvements, and contributions that align with the project's security-first focus. Before submitting larger changes, open an issue to discuss scope and design. When contributing, please keep PRs focused and ensure existing tests pass. We especially value feedback from teams using VibeSafe in regulated, air-gapped, or sovereign-cloud environments.

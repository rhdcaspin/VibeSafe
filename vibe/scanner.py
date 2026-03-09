"""Vulnerability scanning for Python dependencies and container images."""

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Default container image used in pod template
DEFAULT_CONTAINER_IMAGE = "registry.access.redhat.com/ubi9/python-39"


@dataclass
class VulnFinding:
    """A single vulnerability finding."""

    component: str
    version: str | None
    vuln_id: str
    severity: str
    description: str
    fix_versions: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class ScanResult:
    """Aggregated scan result."""

    passed: bool
    findings: list[VulnFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def scan_pip_packages(packages: list[str]) -> ScanResult:
    """
    Scan Python packages for known vulnerabilities using pip-audit.
    Returns findings and any scan errors.
    """
    if not packages:
        return ScanResult(passed=True)

    findings: list[VulnFinding] = []
    errors: list[str] = []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as f:
        f.write("\n".join(f"{p}>=0" for p in packages))
        req_path = f.name

    try:
        result = subprocess.run(
            ["pip-audit", "-r", req_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        errors.append(
            "pip-audit not found. Install with: pip install pip-audit"
        )
        return ScanResult(passed=False, errors=errors)
    except subprocess.TimeoutExpired:
        errors.append("pip-audit timed out after 60s")
        return ScanResult(passed=False, errors=errors)
    finally:
        Path(req_path).unlink(missing_ok=True)

    if result.returncode != 0 and not result.stdout:
        errors.append(result.stderr or "pip-audit failed")
        return ScanResult(passed=False, errors=errors)

    # Parse JSON output
    try:
        import json

        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        if result.stderr:
            errors.append(result.stderr)
        return ScanResult(passed=result.returncode == 0, findings=findings, errors=errors)

    # pip-audit JSON: { "dependencies": [ { "name", "version", "vulns": [ { "id", "description", "fix_versions": [{ "version" }] } ] } ] }
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fix_vers = [fv.get("version", "") for fv in vuln.get("fix_versions", [])]
            findings.append(
                VulnFinding(
                    component=dep.get("name", "unknown"),
                    version=dep.get("version"),
                    vuln_id=vuln.get("id", ""),
                    severity="UNKNOWN",  # pip-audit doesn't always provide severity
                    description=vuln.get("description", ""),
                    fix_versions=fix_vers,
                    source="pip-audit",
                )
            )

    passed = result.returncode == 0
    return ScanResult(passed=passed, findings=findings, errors=errors)


def scan_container_image(image: str = DEFAULT_CONTAINER_IMAGE) -> ScanResult:
    """
    Scan container image for vulnerabilities using Trivy (if installed).
    """
    findings: list[VulnFinding] = []
    errors: list[str] = []

    try:
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--no-progress",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        errors.append(
            "Trivy not found. Install from https://github.com/aquasecurity/trivy "
            "for container scanning."
        )
        return ScanResult(passed=True, errors=errors)  # Don't fail deploy if trivy missing
    except subprocess.TimeoutExpired:
        errors.append("Trivy timed out after 120s")
        return ScanResult(passed=False, errors=errors)

    try:
        import json

        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        errors.append(result.stderr or "Trivy output parse failed")
        return ScanResult(passed=False, errors=errors)

    for result_data in data.get("Results", []):
        for vuln in result_data.get("Vulnerabilities", []):
            findings.append(
                VulnFinding(
                    component=vuln.get("PkgName", "unknown"),
                    version=vuln.get("InstalledVersion"),
                    vuln_id=vuln.get("VulnerabilityID", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    description=vuln.get("Title", vuln.get("Description", "")),
                    fix_versions=[vuln.get("FixedVersion", "")] if vuln.get("FixedVersion") else [],
                    source="trivy",
                )
            )

    # Trivy exit 1 = vulns found (or error)
    passed = result.returncode == 0 and not findings
    return ScanResult(passed=passed, findings=findings, errors=errors)


def run_full_scan(
    pip_packages: list[str],
    container_image: str = DEFAULT_CONTAINER_IMAGE,
    skip_container: bool = False,
) -> tuple[ScanResult, ScanResult]:
    """Run both pip and container scans. Returns (pip_result, container_result)."""
    pip_result = scan_pip_packages(pip_packages)
    if skip_container:
        return pip_result, ScanResult(passed=True)
    container_result = scan_container_image(container_image)
    return pip_result, container_result

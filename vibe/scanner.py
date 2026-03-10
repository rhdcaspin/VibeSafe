"""Vulnerability scanning for Python dependencies and container images."""

import json
import os
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


def _parse_roxctl_vulnerabilities(data: dict) -> list[VulnFinding]:
    """Parse RHACS/roxctl image scan JSON output into VulnFinding list."""
    findings: list[VulnFinding] = []

    def add_vuln(
        component: str,
        version: str | None,
        vuln_id: str,
        severity: str,
        description: str,
        fix_version: str | None = None,
    ) -> None:
        fix_versions = [fix_version] if fix_version else []
        findings.append(
            VulnFinding(
                component=component,
                version=version,
                vuln_id=vuln_id,
                severity=severity or "UNKNOWN",
                description=description or "",
                fix_versions=fix_versions,
                source="roxctl",
            )
        )

    # RHACS/StackRox scan output: image.scan, scan, or scanResults
    scan = (
        data.get("image", {}).get("scan")
        or data.get("scan")
        or data.get("scanResults")
        or data
    )
    components = scan.get("components", scan.get("component", [])) if isinstance(scan, dict) else []
    if not isinstance(components, list):
        components = [components] if components else []

    for comp in components:
        name = comp.get("name", comp.get("layer", "unknown"))
        version = comp.get("version")
        vulns = comp.get("vulns", comp.get("vulnerabilities", []))
        for v in vulns:
            add_vuln(
                component=name,
                version=version,
                vuln_id=v.get("id", v.get("cve", v.get("vulnerabilityId", ""))),
                severity=v.get("severity", "UNKNOWN"),
                description=v.get("summary", v.get("description", v.get("link", ""))),
                fix_version=v.get("fixedBy", v.get("fixedIn", v.get("fixedVersion"))),
            )

    # Alternative: flat vulns array
    for v in data.get("vulnerabilities", []):
        add_vuln(
            component=v.get("component", v.get("name", "unknown")),
            version=v.get("version"),
            vuln_id=v.get("id", v.get("cve", "")),
            severity=v.get("severity", "UNKNOWN"),
            description=v.get("summary", v.get("description", "")),
            fix_version=v.get("fixedBy", v.get("fixedIn")),
        )

    return findings


def _scan_container_image_trivy(image: str) -> ScanResult:
    """
    Scan container image using Trivy (fallback when roxctl/RHACS not available).
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
            "No container scanner available. Install roxctl (RHACS) or Trivy "
            "(https://github.com/aquasecurity/trivy) for image scanning."
        )
        return ScanResult(passed=True, errors=errors)
    except subprocess.TimeoutExpired:
        errors.append("Trivy timed out after 120s")
        return ScanResult(passed=False, errors=errors)

    try:
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

    passed = result.returncode == 0 and not findings
    return ScanResult(passed=passed, findings=findings, errors=errors)


def scan_container_image(image: str = DEFAULT_CONTAINER_IMAGE) -> ScanResult:
    """
    Scan container image for vulnerabilities using roxctl (RHACS CLI).

    Requires RHACS Central to be running and configured via environment:
    - ROX_CENTRAL_ADDRESS: Central API endpoint (e.g. staging.demo.stackrox.com:443)
    - ROX_API_TOKEN: API token from RHACS Platform Configuration → API Tokens
    - ROX_INSECURE: set to 'true' for self-signed certs (e.g. local Central)
    """
    findings: list[VulnFinding] = []
    errors: list[str] = []

    central = os.environ.get("ROX_CENTRAL_ADDRESS")
    token = os.environ.get("ROX_API_TOKEN")
    if not central or not token:
        # Fall back to Trivy when RHACS not configured
        return _scan_container_image_trivy(image)

    cmd = [
        "roxctl",
        "image",
        "scan",
        "--image",
        image,
        "--output",
        "json",
        "-e",
        central,
    ]
    if os.environ.get("ROX_INSECURE", "").lower() in ("true", "1", "yes"):
        cmd.append("--insecure")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "ROX_API_TOKEN": token},
        )
    except FileNotFoundError:
        # Fall back to Trivy if roxctl not installed
        return _scan_container_image_trivy(image)
    except subprocess.TimeoutExpired:
        errors.append("roxctl image scan timed out after 180s")
        return ScanResult(passed=False, errors=errors)

    if result.returncode != 0 and result.stderr:
        errors.append(result.stderr.strip())
        return ScanResult(passed=False, errors=errors)

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        errors.append(result.stderr or "roxctl output parse failed")
        return ScanResult(passed=False, errors=errors)

    findings = _parse_roxctl_vulnerabilities(data)

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

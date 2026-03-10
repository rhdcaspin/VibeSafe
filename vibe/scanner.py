"""Vulnerability scanning for Python dependencies and container images."""

import csv
import json
import os
import shutil
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


CRITICAL_SEVERITY = "CRITICAL"


def has_critical_vulns(result: ScanResult) -> bool:
    """Return True if any finding has CRITICAL severity."""
    return any(
        f.severity.upper() == CRITICAL_SEVERITY
        for f in result.findings
    )


def write_findings_to_csv(
    pip_result: ScanResult,
    container_result: ScanResult,
    path: Path,
) -> None:
    """Write all vulnerability findings to a CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    all_findings: list[VulnFinding] = []
    for f in pip_result.findings:
        all_findings.append(f)
    for f in container_result.findings:
        all_findings.append(f)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["source", "component", "version", "vuln_id", "severity", "description", "fix_versions"]
        )
        for v in all_findings:
            fix_str = "; ".join(v.fix_versions) if v.fix_versions else ""
            writer.writerow(
                [
                    v.source,
                    v.component,
                    v.version or "",
                    v.vuln_id,
                    v.severity,
                    (v.description or "")[:500],
                    fix_str,
                ]
            )


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


def _find_roxctl() -> str | None:
    """Return path to roxctl, or None if not found. Checks PATH then ./roxctl."""
    if shutil.which("roxctl"):
        return "roxctl"
    cwd_roxctl = Path.cwd() / "roxctl"
    if cwd_roxctl.is_file() and os.access(cwd_roxctl, os.X_OK):
        return str(cwd_roxctl)
    return None


def scan_container_image(image: str = DEFAULT_CONTAINER_IMAGE) -> ScanResult:
    """
    Scan container image for vulnerabilities using roxctl (RHACS CLI).
    Requires ROX_CENTRAL_ADDRESS and ROX_API_TOKEN. See docs/RHACS_KIND.md.
    """
    central = os.environ.get("ROX_CENTRAL_ADDRESS")
    token = os.environ.get("ROX_API_TOKEN")
    if not central or not token:
        return ScanResult(
            passed=True,
            errors=[
                "roxctl requires ROX_CENTRAL_ADDRESS and ROX_API_TOKEN. "
                "Set them to connect to RHACS Central (see docs/RHACS_KIND.md)."
            ],
        )

    roxctl_path = _find_roxctl()
    if not roxctl_path:
        return ScanResult(
            passed=True,
            errors=[
                "roxctl not found in PATH or current directory. "
                "Install from RHACS Central (Help → About) or add to PATH."
            ],
        )

    cmd = [
        roxctl_path,
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

    findings: list[VulnFinding] = []
    errors: list[str] = []

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "ROX_API_TOKEN": token},
        )
    except FileNotFoundError:
        errors.append(
            "roxctl not found. Install from RHACS Central (Help → About) or Red Hat Ecosystem Catalog."
        )
        return ScanResult(passed=True, errors=errors)
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

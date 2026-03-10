"""Typer CLI entrypoint for vibe."""

from pathlib import Path

import typer

from vibe.analyzer import analyze_script
from vibe.generator import ManifestGenerator
from vibe.deployer import apply_manifests
from vibe.scanner import run_full_scan, VulnFinding, DEFAULT_CONTAINER_IMAGE

app = typer.Typer(invoke_without_command=True)


@app.callback()
def main(ctx: typer.Context) -> None:
    """Deploy Python vibe code to Kubernetes with zero-trust security."""
    if ctx.invoked_subcommand is None:
        typer.echo("Use 'vibe deploy --help' or 'vibe scan --help' for usage.")
        raise typer.Exit(0)


def _format_finding(f: VulnFinding) -> str:
    fix = f" (fix: {', '.join(f.fix_versions)})" if f.fix_versions else ""
    desc = (f.description or "")[:80]
    return f"  [{f.vuln_id or 'N/A'}] {f.component}@{f.version or '?'}: {desc}{fix}"


def _run_scan_and_report(
    pip_packages: list[str],
    container_image: str,
    skip_container: bool,
    *,
    fail_on_vuln: bool = False,
) -> bool:
    """Run scans and print report. Returns True if all passed."""
    typer.echo("")
    typer.echo("🔒 Vulnerability scan")
    typer.echo("─" * 40)

    pip_result, container_result = run_full_scan(
        pip_packages, container_image, skip_container
    )

    all_passed = True

    if pip_packages:
        typer.echo("  Python packages:")
        if pip_result.errors:
            for e in pip_result.errors:
                typer.echo(f"    ⚠️  {e}")
            all_passed = False
        elif pip_result.findings:
            for f in pip_result.findings:
                typer.echo(_format_finding(f))
            typer.echo(f"    → {len(pip_result.findings)} vulnerability(ies) found")
            all_passed = False
        else:
            typer.echo("    ✓ No known vulnerabilities")
    else:
        typer.echo("  Python packages: (none)")

    if not skip_container:
        typer.echo("  Container image:")
        if container_result.errors:
            for e in container_result.errors:
                typer.echo(f"    ⚠️  {e}")
        elif container_result.findings:
            for f in container_result.findings[:10]:  # Limit output
                typer.echo(_format_finding(f))
            if len(container_result.findings) > 10:
                typer.echo(f"    ... and {len(container_result.findings) - 10} more")
            typer.echo(f"    → {len(container_result.findings)} vulnerability(ies) found")
            all_passed = False
        else:
            typer.echo("    ✓ No known vulnerabilities")

    typer.echo("─" * 40)
    typer.echo("")

    if fail_on_vuln and not all_passed:
        typer.echo("Deployment blocked: vulnerabilities found. Use --no-scan to skip.", err=True)
        raise typer.Exit(1)

    return all_passed


@app.command()
def deploy(
    script_path: Path = typer.Argument(..., help="Path to the Python script to deploy"),
    project: str = typer.Option(..., "--project", "-p", help="Project name for the deployment"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate manifests without applying to cluster"),
    no_spire: bool = typer.Option(
        False, "--no-spire",
        help="Skip SPIRE/SPIFFE volume (use for Kind/minikube without SPIRE installed)",
    ),
    pip: list[str] = typer.Option(
        [],
        "--pip", "-P",
        help="Pip packages to install (e.g. requests). Auto-added for requests/urllib when detected.",
    ),
    scan: bool = typer.Option(
        True, "--scan/--no-scan",
        help="Run vulnerability scan before deploy (pip-audit for deps, roxctl/Trivy for image).",
    ),
) -> None:
    """
    Analyze a Python script, generate zero-trust K8s manifests, and deploy (or dry-run).
    """
    if not script_path.exists():
        typer.echo(f"Error: File not found: {script_path}", err=True)
        raise typer.Exit(1)

    typer.echo(f"🔍 Analyzing {script_path}...")
    file_content = script_path.read_text()

    profile = analyze_script(file_content)
    findings = profile.get("findings", {})

    typer.echo("")
    typer.echo("📋 Security analysis findings:")
    typer.echo("─" * 40)

    high_risk = findings.get("high_risk_modules", [])
    if high_risk:
        typer.echo(f"  ⚠️  High risk: {', '.join(high_risk)}")
        typer.echo("      → OS access, subprocess, or system-level modules")
    else:
        typer.echo("  ✓  High risk: None detected")

    network = findings.get("network_modules", [])
    if network:
        typer.echo(f"  🌐 Network egress: {', '.join(network)}")
        typer.echo("      → Network policy will allow outbound HTTP/HTTPS")
    else:
        typer.echo("  ✓  Network egress: None (default deny)")

    typer.echo("─" * 40)
    typer.echo("")

    if no_spire:
        typer.echo("  📌 Local mode: SPIRE volume disabled (--no-spire)")
    typer.echo("")
    typer.echo("🛡️ Generating Zero-Trust manifests (SELinux, VAP, SPIRE)...")

    generator = ManifestGenerator(
        profile,
        project,
        vibe_code=file_content,
        use_spire=not no_spire,
        pip_packages=pip if pip else None,
    )
    pip_packages_list = generator.pip_packages

    if scan:
        _run_scan_and_report(
            pip_packages_list,
            DEFAULT_CONTAINER_IMAGE,
            skip_container=False,
            fail_on_vuln=False,
        )

    yaml_strings = generator.generate()

    output_dir = Path(".vibe-build")
    output_dir.mkdir(exist_ok=True)

    for name, content in yaml_strings.items():
        out_path = output_dir / name
        out_path.write_text(content)

    if dry_run:
        typer.echo(f"✅ Dry run complete. Manifests saved to {output_dir}/")
        return

    typer.echo("📤 Applying manifests to cluster...")

    try:
        apply_manifests(list(yaml_strings.values()))
        typer.echo("✅ Deployment complete.")
    except Exception as e:
        typer.echo(f"Error applying manifests: {e}", err=True)
        raise typer.Exit(1)


@app.command("scan")
def scan_cmd(
    script_path: Path = typer.Argument(..., help="Path to the Python script to scan"),
    project: str = typer.Option("default", "--project", "-p", help="Project name (for context)"),
    image: str = typer.Option(
        DEFAULT_CONTAINER_IMAGE,
        "--image", "-i",
        help="Container image to scan (default: UBI Python)",
    ),
    no_container: bool = typer.Option(
        False, "--no-container",
        help="Skip container image scan (pip packages only)",
    ),
    fail_on_vuln: bool = typer.Option(
        False, "--strict", "-s",
        help="Exit with error if vulnerabilities found",
    ),
) -> None:
    """
    Run vulnerability scans on Python dependencies and container image.
    Requires: pip-audit (pip install pip-audit). Container scan: roxctl (RHACS) or Trivy.
    """
    if not script_path.exists():
        typer.echo(f"Error: File not found: {script_path}", err=True)
        raise typer.Exit(1)

    typer.echo(f"🔍 Analyzing {script_path}...")
    profile = analyze_script(script_path.read_text())
    generator = ManifestGenerator(
        profile, project, vibe_code="", pip_packages=None
    )
    pip_packages_list = generator.pip_packages

    _run_scan_and_report(
        pip_packages_list,
        image,
        skip_container=no_container,
        fail_on_vuln=fail_on_vuln,
    )

    typer.echo("✅ Scan complete.")

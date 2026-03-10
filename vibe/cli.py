"""Typer CLI entrypoint for vibe."""

from pathlib import Path
from typing import Optional

import typer


# Directories to exclude from collection (venv, cache, etc.)
_EXCLUDE_DIRS = (".venv", "venv", "env", ".env", "__pycache__", ".git", "node_modules")


def _collect_python_files(paths: list[Path]) -> list[tuple[Path, str, str]]:
    """
    Collect Python files from paths. Each path can be a file or directory.
    Returns list of (absolute_path, configmap_key, mount_path).
    configmap_key: key in ConfigMap (no slashes). mount_path: path in container (preserves dirs).
    Excludes .venv, venv, __pycache__, .git, etc.
    """
    collected: list[tuple[Path, str, str]] = []
    seen_keys: set[str] = set()

    def add_file(p: Path, cm_key: str | None = None, mount_path: str | None = None) -> None:
        if p.suffix != ".py":
            return
        cm_key = cm_key or p.name
        mount_path = mount_path or p.name
        if cm_key in seen_keys:
            return
        seen_keys.add(cm_key)
        collected.append((p.resolve(), cm_key, mount_path))

    def _skip(path: Path, base: Path) -> bool:
        try:
            rel = path.relative_to(base)
            return any(rel.parts[i] in _EXCLUDE_DIRS for i in range(len(rel.parts)))
        except ValueError:
            return False

    for path in paths:
        p = Path(path).resolve()
        if not p.exists():
            continue
        if p.is_file():
            add_file(p)
        else:
            for f in sorted(p.rglob("*.py")):
                if _skip(f, p):
                    continue
                rel = f.relative_to(p)
                cm_key = str(rel).replace("/", "_").replace("\\", "_")
                mount_path = f"{p.name}/{rel}".replace("\\", "/")
                add_file(f, cm_key, mount_path)

    return collected


def _merge_profiles(profiles: list[dict]) -> dict:
    """Merge multiple analyzer profiles into one."""
    if not profiles:
        return {}
    merged: dict = {
        "needs_network_egress": any(p.get("needs_network_egress") for p in profiles),
        "high_risk": any(p.get("high_risk") for p in profiles),
        "findings": {
            "network_modules": [],
            "high_risk_modules": [],
            "pip_modules": [],
        },
        "egress_targets": [],
    }
    for p in profiles:
        for key in ("network_modules", "high_risk_modules", "pip_modules"):
            merged["findings"][key] = sorted(
                set(merged["findings"][key]) | set(p.get("findings", {}).get(key, []))
            )
        for t in p.get("egress_targets", []):
            key = (t.get("hostname"), t.get("port"))
            if key not in {(x.get("hostname"), x.get("port")) for x in merged["egress_targets"]}:
                merged["egress_targets"].append(t)
    return merged


def _resolve_entry_point(files: list[tuple[Path, str, str]], main: str = "") -> str:
    """Return the mount_path to use as entry point (path in container)."""
    mount_paths = [mp for _, _, mp in files]
    keys = [k for _, k, _ in files]
    if main and main.strip():
        main_path = Path(main)
        if main in mount_paths:
            return main
        if main_path.name in mount_paths:
            return main_path.name
        if main in keys:
            return next(mp for _, k, mp in files if k == main)
        # Match by absolute path (e.g. ../aifeaturepriortization/rox_feature_export_notebooklm.py)
        main_abs = main_path.resolve()
        for abs_path, _, mount_path in files:
            if abs_path == main_abs:
                return mount_path
        # Fallback: match by filename
        for _, _, mount_path in files:
            if mount_path.endswith(main_path.name):
                return mount_path
        return main_path.name
    for preferred in ("__main__.py", "main.py", "app.py"):
        if preferred in mount_paths:
            return preferred
        if preferred in keys:
            return next(mp for _, k, mp in files if k == preferred)
    return mount_paths[0] if mount_paths else "vibe_code.py"

from vibe.analyzer import analyze_script
from vibe.builder import (
    build_image,
    is_kind_cluster,
    load_to_kind,
    prepare_build_context,
    push_to_registry,
)
from vibe.generator import ManifestGenerator
from vibe.deployer import apply_manifests
from vibe.scanner import (
    DEFAULT_CONTAINER_IMAGE,
    VulnFinding,
    has_critical_vulns,
    run_full_scan,
    write_findings_to_csv,
)

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
    csv_output: Path | None = None,
) -> bool:
    """Run scans and print report. Returns True if all passed. Exits on CRITICAL vulns."""
    typer.echo("")
    typer.echo("🔒 Vulnerability scan")
    typer.echo("─" * 40)

    pip_result, container_result = run_full_scan(
        pip_packages, container_image, skip_container
    )

    if csv_output:
        write_findings_to_csv(pip_result, container_result, csv_output)
        typer.echo(f"  📄 Results saved to {csv_output}")

    if has_critical_vulns(pip_result) or has_critical_vulns(container_result):
        typer.echo("", err=True)
        typer.echo("❌ CRITICAL vulnerabilities found. Stopping.", err=True)
        if csv_output:
            typer.echo(f"   See {csv_output} for details.", err=True)
        raise typer.Exit(1)

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
    script_path: list[Path] = typer.Argument(
        ...,
        help="Python script(s) or directory to deploy. Multiple paths allowed.",
    ),
    project: str = typer.Option(..., "--project", "-p", help="Project name for the deployment"),
    main: str = typer.Option(
        "",
        "--main", "-m",
        help="Entry point script (e.g. main.py). Default: __main__.py, main.py, or first file.",
    ),
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
        help="Run vulnerability scan before deploy (pip-audit for deps, roxctl for image).",
    ),
    csv: Path | None = typer.Option(
        None,
        "--csv", "-o",
        path_type=Path,
        help="Write vulnerability findings to CSV file. Stops on CRITICAL vulns.",
    ),
    no_build: bool = typer.Option(
        False, "--no-build",
        help="Skip container build; use ConfigMap deploy (legacy) or --image if provided.",
    ),
    image: Optional[str] = typer.Option(
        None,
        "--image", "-i",
        help="Container image to use. Builds and uses vibesafe-<project>:latest if not set.",
    ),
    registry: Optional[str] = typer.Option(
        None,
        "--registry",
        help="Push image to registry (e.g. localhost:5000 or quay.io/user). Auto-loads to Kind if detected.",
    ),
) -> None:
    """
    Analyze Python script(s), generate zero-trust K8s manifests, and deploy (or dry-run).
    Pass a directory to package all .py files, or multiple script paths.
    """
    files = _collect_python_files([Path(p) for p in script_path])
    if not files:
        typer.echo("Error: No Python files found.", err=True)
        raise typer.Exit(1)

    entry_point = _resolve_entry_point(files, main)
    typer.echo(f"🔍 Analyzing {len(files)} file(s), entry: {entry_point}")

    profiles = []
    vibe_files: dict[str, str] = {}
    configmap_items: list[dict[str, str]] = []
    for path, cm_key, mount_path in files:
        content = path.read_text()
        vibe_files[cm_key] = content
        configmap_items.append({"key": cm_key, "path": mount_path})
        profiles.append(analyze_script(content))

    profile = _merge_profiles(profiles)
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
    egress_targets = profile.get("egress_targets", [])
    if network:
        typer.echo(f"  🌐 Network egress: {', '.join(network)}")
        if egress_targets:
            hosts = sorted({t["hostname"] for t in egress_targets})
            ports = sorted({t["port"] for t in egress_targets})
            typer.echo(f"      → Allowing ports {ports} to {hosts}")
        else:
            typer.echo("      → Network policy will allow outbound HTTP/HTTPS (ports 80, 443)")
    else:
        typer.echo("  ✓  Network egress: None (default deny)")

    typer.echo("─" * 40)
    typer.echo("")

    if no_spire:
        typer.echo("  📌 Local mode: SPIRE volume disabled (--no-spire)")
    typer.echo("")

    pip_packages_list = ManifestGenerator(
        profile, project, vibe_code="", pip_packages=pip if pip else None
    ).pip_packages

    image_name: Optional[str] = image
    if not no_build and image_name is None:
        typer.echo("🐳 Building container image...")
        output_dir = Path(".vibe-build") / project
        build_dir = output_dir / "build"
        prepare_build_context(
            build_dir,
            vibe_files,
            configmap_items,
            entry_point,
            pip_packages_list,
        )
        image_name = f"vibesafe-{project}:latest"
        build_image(build_dir, image_name)
        if is_kind_cluster():
            typer.echo("  Loading image into Kind cluster...")
            load_to_kind(image_name)
        elif registry:
            typer.echo(f"  Pushing to registry {registry}...")
            image_name = push_to_registry(image_name, registry)
    elif registry and image_name:
        typer.echo(f"  Pushing image to registry {registry}...")
        image_name = push_to_registry(image_name, registry)

    typer.echo("🛡️ Generating Zero-Trust manifests (SELinux, VAP, SPIRE)...")

    generator = ManifestGenerator(
        profile,
        project,
        vibe_files=vibe_files,
        configmap_items=configmap_items,
        entry_point=entry_point,
        use_spire=not no_spire,
        pip_packages=pip if pip else None,
        image_name=image_name,
    )
    pip_packages_list = generator.pip_packages

    if scan:
        csv_path = csv or (Path(".vibe-build") / project / "vulnerability-report.csv")
        scan_image = image_name or DEFAULT_CONTAINER_IMAGE
        _run_scan_and_report(
            pip_packages_list,
            scan_image,
            skip_container=False,
            fail_on_vuln=False,
            csv_output=csv_path,
        )

    yaml_strings = generator.generate()

    output_dir = Path(".vibe-build") / project
    output_dir.mkdir(parents=True, exist_ok=True)

    for name, content in yaml_strings.items():
        out_path = output_dir / name
        out_path.write_text(content)

    if dry_run:
        typer.echo(f"✅ Dry run complete. Manifests saved to {output_dir}/")
        return

    typer.echo("📤 Applying manifests to cluster...")

    try:
        apply_manifests(list(yaml_strings.values()))
        typer.echo(f"✅ Deployment complete. Configuration files in {output_dir}/")
    except Exception as e:
        typer.echo(f"Error applying manifests: {e}", err=True)
        raise typer.Exit(1)


@app.command("scan")
def scan_cmd(
    script_path: list[Path] = typer.Argument(
        ...,
        help="Python script(s) or directory to scan.",
    ),
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
    csv: Path | None = typer.Option(
        None,
        "--csv", "-o",
        path_type=Path,
        help="Write vulnerability findings to CSV. Stops on CRITICAL vulns.",
    ),
) -> None:
    """
    Run vulnerability scans on Python dependencies and container image.
    Requires: pip-audit (pip install pip-audit), roxctl for container (ROX_CENTRAL_ADDRESS, ROX_API_TOKEN).
    """
    files = _collect_python_files([Path(p) for p in script_path])
    if not files:
        typer.echo("Error: No Python files found.", err=True)
        raise typer.Exit(1)

    typer.echo(f"🔍 Analyzing {len(files)} file(s)...")
    profiles = [analyze_script(p.read_text()) for p, _, _ in files]
    profile = _merge_profiles(profiles)
    generator = ManifestGenerator(
        profile, project, vibe_code="", pip_packages=None
    )
    pip_packages_list = generator.pip_packages

    csv_path = csv or Path("vulnerability-report.csv")
    _run_scan_and_report(
        pip_packages_list,
        image,
        skip_container=no_container,
        fail_on_vuln=fail_on_vuln,
        csv_output=csv_path,
    )

    typer.echo("✅ Scan complete.")

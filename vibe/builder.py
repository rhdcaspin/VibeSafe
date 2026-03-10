"""Container image build for VibeSafe deployments."""

import shutil
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_BASE_IMAGE = "registry.access.redhat.com/ubi9/python-39"


def _get_container_cmd() -> str:
    """Return 'podman' or 'docker'."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    raise RuntimeError("Neither podman nor docker found. Install one to build images.")


def is_kind_cluster() -> bool:
    """Check if current context is a Kind cluster."""
    try:
        result = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and "kind" in (result.stdout or "").lower()
    except Exception:
        return False


def push_to_registry(image_name: str, registry: str) -> str:
    """Tag and push image to registry. Returns final image name."""
    cmd = _get_container_cmd()
    # registry might be "localhost:5000" or "quay.io/user"
    if "/" in registry.rstrip("/"):
        full_name = f"{registry.rstrip('/')}/{image_name}"
    else:
        # registry is host:port
        full_name = f"{registry}/{image_name}"
    subprocess.run(
        [cmd, "tag", image_name, full_name],
        check=True,
        capture_output=True,
        timeout=10,
    )
    subprocess.run(
        [cmd, "push", full_name],
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return full_name


def prepare_build_context(
    build_dir: Path,
    vibe_files: dict[str, str],
    configmap_items: list[dict[str, str]],
    entry_point: str,
    pip_packages: list[str],
) -> None:
    """Write app code and Dockerfile to build_dir."""
    build_dir.mkdir(parents=True, exist_ok=True)
    app_dir = build_dir / "app"
    app_dir.mkdir(exist_ok=True)

    for item in configmap_items:
        path = Path(item["path"])
        content = vibe_files.get(item["key"], "")
        full_path = app_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)

    dockerfile = f"""FROM {DEFAULT_BASE_IMAGE}
COPY app /app
WORKDIR /app
"""
    if pip_packages:
        dockerfile += f"""
RUN pip3 install --target /tmp/packages {' '.join(pip_packages)}
ENV PYTHONPATH=/app:/tmp/packages
"""
    elif "/" in entry_point:
        dockerfile += """
ENV PYTHONPATH=/app
"""
    dockerfile += f"""
CMD ["python3", "/app/{entry_point}"]
"""
    (build_dir / "Dockerfile").write_text(dockerfile)


def build_image(
    build_dir: Path,
    image_name: str,
) -> str:
    """Build container image. Returns image name.
    Uses --network=host for Podman so pip install can reach PyPI during build.
    """
    cmd = _get_container_cmd()
    build_args = [cmd, "build", "-t", image_name]
    # Use host network so pip install can reach PyPI during build
    if cmd == "podman":
        build_args.append("--network=host")
    elif cmd == "docker":
        build_args.extend(["--network", "host"])
    build_args.append(".")
    result = subprocess.run(
        build_args,
        cwd=build_dir,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        msg = f"Container build failed (exit {result.returncode}).\n"
        if result.stderr:
            msg += f"stderr:\n{result.stderr}"
        if result.stdout and "Error" not in (result.stderr or ""):
            msg += f"\nstdout (last 500 chars):\n...{result.stdout[-500:]}"
        raise RuntimeError(msg)
    return image_name


def load_to_kind(image_name: str) -> None:
    """Load image into Kind cluster. Uses podman save|kind load for Podman."""
    cmd = _get_container_cmd()
    if cmd == "podman":
        proc = subprocess.Popen(
            ["podman", "save", image_name],
            stdout=subprocess.PIPE,
        )
        try:
            subprocess.run(
                ["kind", "load", "image-archive", "-"],
                stdin=proc.stdout,
                check=True,
                capture_output=True,
                timeout=120,
            )
        finally:
            proc.wait()
    else:
        subprocess.run(
            ["kind", "load", "docker-image", image_name],
            check=True,
            capture_output=True,
            timeout=120,
        )

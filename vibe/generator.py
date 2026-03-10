"""Jinja2-based manifest generation from security profile."""

import base64
import gzip
import io
import tarfile
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader


class ManifestGenerator:
    """
    Generates Kubernetes manifests from a security profile and project name.
    """

    # Map analyzer module names to pip package names
    PIP_MODULE_MAP = {"requests": "requests", "urllib": "urllib3", "http": "httpx", "spiffe": "spiffe"}

    def __init__(
        self,
        security_profile: dict[str, Any],
        project_name: str,
        vibe_code: str = "",
        vibe_files: dict[str, str] | None = None,
        configmap_items: list[dict[str, str]] | None = None,
        entry_point: str = "vibe_code.py",
        use_spire: bool = True,
        pip_packages: list[str] | None = None,
        *,
        image_name: str | None = None,
    ) -> None:
        self.profile = security_profile
        self.project_name = project_name
        self.entry_point = entry_point
        self.vibe_files = vibe_files or {}
        self.configmap_items = configmap_items
        if not self.vibe_files and vibe_code:
            self.vibe_files = {"vibe_code.py": vibe_code}
            self.configmap_items = [{"key": "vibe_code.py", "path": "vibe_code.py"}]
        if not self.vibe_files:
            self.vibe_files = {"vibe_code.py": "# (vibe code not embedded)\n"}
            self.configmap_items = [{"key": "vibe_code.py", "path": "vibe_code.py"}]
        if not self.configmap_items:
            self.configmap_items = [{"key": k, "path": k} for k in self.vibe_files]
        self.use_spire = use_spire
        self.pip_packages = pip_packages or self._auto_pip_packages()
        self.image_name = image_name
        self._env = self._load_templates()

    def _auto_pip_packages(self) -> list[str]:
        """Auto-detect pip packages from analyzer findings."""
        pip_mods = set(
            self.profile.get("findings", {}).get("pip_modules", [])
        ) | set(self.profile.get("findings", {}).get("network_modules", []))
        packages = []
        for mod in pip_mods:
            if mod in self.PIP_MODULE_MAP:
                pkg = self.PIP_MODULE_MAP[mod]
                if pkg not in packages:
                    packages.append(pkg)
        return packages

    def _load_templates(self) -> Environment:
        template_dir = Path(__file__).parent / "templates"
        return Environment(
            loader=FileSystemLoader(str(template_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _make_vibe_archive_b64(self) -> str:
        """Create gzipped tarball of vibe files and return base64. Reduces ConfigMap size."""
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            with tarfile.TarFile(fileobj=gz, mode="w") as tar:
                for item in self.configmap_items:
                    key, path = item["key"], item["path"]
                    content = self.vibe_files.get(key, "").encode()
                    info = tarfile.TarInfo(name=path)
                    info.size = len(content)
                    tar.addfile(info, io.BytesIO(content))
        return base64.b64encode(buf.getvalue()).decode("ascii")

    def generate(self) -> dict[str, str]:
        """
        Render all templates and return a dict of filename -> YAML content.
        When image_name is set, uses container image (no ConfigMap). Otherwise uses ConfigMap.
        """
        egress_targets = self.profile.get("egress_targets", [])
        egress_ports = sorted(set(p["port"] for p in egress_targets))
        egress_hostnames = sorted({p["hostname"] for p in egress_targets})
        if not egress_ports and self.profile.get("needs_network_egress"):
            egress_ports = [80, 443]  # Fallback when no URLs extracted

        context: dict[str, Any] = {
            "project_name": self.project_name,
            "needs_network_egress": self.profile.get("needs_network_egress", False),
            "high_risk": self.profile.get("high_risk", False),
            "entry_point": self.entry_point,
            "use_spire": self.use_spire,
            "pip_packages": self.pip_packages,
            "egress_targets": egress_targets,
            "egress_ports": egress_ports,
            "egress_hostnames": egress_hostnames,
        }

        use_image = bool(self.image_name)
        if use_image:
            context["image_name"] = self.image_name
            context["image_pull_policy"] = "Never" if self._is_local_image() else "IfNotPresent"
        else:
            vibe_archive_b64 = self._make_vibe_archive_b64()
            context["vibe_archive_b64"] = vibe_archive_b64
            context["configmap_items"] = self.configmap_items

        outputs: dict[str, str] = {}
        templates = [
            ("vap.yaml.j2", "vap.yaml"),
            ("vap_binding.yaml.j2", "vap_binding.yaml"),
            ("netpol.yaml.j2", "netpol.yaml"),
        ]
        if not use_image:
            templates.insert(0, ("configmap.yaml.j2", "configmap.yaml"))
        templates.append(
            ("pod-image.yaml.j2", "pod.yaml") if use_image else ("pod.yaml.j2", "pod.yaml")
        )

        for template_name, output_name in templates:
            template = self._env.get_template(template_name)
            outputs[output_name] = template.render(**context)

        return outputs

    def _is_local_image(self) -> bool:
        """True if image is local (no registry, or localhost)."""
        if not self.image_name:
            return False
        # No slash = local (e.g. vibesafe-project:latest)
        if "/" not in self.image_name.split(":")[0]:
            return True
        # localhost or 127.0.0.1 = local
        name = self.image_name.lower()
        return "localhost" in name or "127.0.0.1" in name

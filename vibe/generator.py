"""Jinja2-based manifest generation from security profile."""

import base64
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
        use_spire: bool = True,
        pip_packages: list[str] | None = None,
    ) -> None:
        self.profile = security_profile
        self.project_name = project_name
        self.vibe_code = vibe_code or "# (vibe code not embedded)\n"
        self.use_spire = use_spire
        self.pip_packages = pip_packages or self._auto_pip_packages()
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

    def generate(self) -> dict[str, str]:
        """
        Render all templates and return a dict of filename -> YAML content.
        """
        # Base64-encode vibe code to avoid YAML parsing issues with """ and other chars
        vibe_b64 = base64.b64encode(self.vibe_code.encode()).decode("ascii")

        context = {
            "project_name": self.project_name,
            "needs_network_egress": self.profile.get("needs_network_egress", False),
            "high_risk": self.profile.get("high_risk", False),
            "vibe_code_b64": vibe_b64,
            "use_spire": self.use_spire,
            "pip_packages": self.pip_packages,
        }

        outputs: dict[str, str] = {}
        # Order matters: VAP must exist before Pod creation for validation
        templates = [
            ("configmap.yaml.j2", "configmap.yaml"),
            ("vap.yaml.j2", "vap.yaml"),
            ("vap_binding.yaml.j2", "vap_binding.yaml"),
            ("netpol.yaml.j2", "netpol.yaml"),
            ("pod.yaml.j2", "pod.yaml"),
        ]

        for template_name, output_name in templates:
            template = self._env.get_template(template_name)
            outputs[output_name] = template.render(**context)

        return outputs

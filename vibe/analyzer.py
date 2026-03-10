"""AST-based code analysis for security profile extraction."""

import ast
from urllib.parse import urlparse
from typing import Any


# Modules that indicate network egress is needed
NETWORK_MODULES = {"requests", "urllib", "http"}

# Modules that flag high risk (OS access, subprocess, etc.)
HIGH_RISK_MODULES = {"os", "sys", "subprocess"}

# Modules that require pip install (network + SPIRE/SPIFFE)
PIP_MODULES = NETWORK_MODULES | {"spiffe"}

# Network call patterns: (module, method) -> typically (url_arg_index,)
NETWORK_CALLS = {
    ("requests", "get"): 0,
    ("requests", "post"): 0,
    ("requests", "put"): 0,
    ("requests", "patch"): 0,
    ("requests", "delete"): 0,
    ("requests", "head"): 0,
    ("requests", "request"): 1,  # method, url
    ("urllib", "urlopen"): 0,
    ("urllib.request", "urlopen"): 0,
    ("http", "get"): 0,
    ("http.client", "request"): 1,
}


def _parse_url_for_egress(url_str: str) -> dict[str, Any] | None:
    """Parse URL and return {scheme, port, hostname}. Returns None if invalid."""
    if not url_str or not isinstance(url_str, str):
        return None
    s = url_str.strip()
    if not s.startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(s)
        scheme = parsed.scheme or "https"
        hostname = parsed.hostname
        port = parsed.port
        if not hostname:
            return None
        if port is None:
            port = 443 if scheme == "https" else 80
        return {"scheme": scheme, "port": port, "hostname": hostname}
    except Exception:
        return None


def _extract_urls_from_ast(tree: ast.AST) -> list[dict[str, Any]]:
    """Extract URLs from AST (requests.get(url), url literals, etc.)."""
    found: list[dict[str, Any]] = []
    seen_ports: set[int] = set()

    def add_from_url(url_val: str) -> None:
        info = _parse_url_for_egress(url_val)
        if info and info["port"] not in seen_ports:
            seen_ports.add(info["port"])
            found.append(info)

    class URLExtractor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # requests.get(url), requests.post(url), urllib.request.urlopen(url)
            if isinstance(node.func, ast.Attribute) and node.args:
                attr = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    mod = node.func.value.id
                elif isinstance(node.func.value, ast.Attribute):
                    mod = getattr(node.func.value.value, "id", "") + "." + node.func.value.attr
                else:
                    mod = ""
                base = mod.split(".")[0]
                url_idx = 0
                if (base, attr) in (("requests", "request"), ("http.client", "request")):
                    url_idx = 1
                if base in ("requests", "urllib", "http") and attr in ("get", "post", "put", "patch", "delete", "head", "urlopen", "request"):
                    if url_idx < len(node.args):
                        arg = node.args[url_idx]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            add_from_url(arg.value)
            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str):
                add_from_url(node.value)
            self.generic_visit(node)

    try:
        URLExtractor().visit(tree)
    except Exception:
        pass
    return found


def analyze_script(file_content: str) -> dict[str, Any]:
    """
    Analyze a Python script using AST to extract its Security Profile.

    Returns a dictionary with:
    - needs_network_egress: True if requests, urllib, or http are imported
    - high_risk: True if os, sys, or subprocess are used
    """
    profile: dict[str, Any] = {
        "needs_network_egress": False,
        "high_risk": False,
        "findings": {"network_modules": [], "high_risk_modules": [], "pip_modules": []},
    }

    try:
        tree = ast.parse(file_content)
    except SyntaxError:
        return profile

    class SecurityVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.imports: set[str] = set()
            self.used_names: set[str] = set()

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                name = alias.name.split(".")[0]
                self.imports.add(name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.module:
                base = node.module.split(".")[0]
                self.imports.add(base)
                for alias in node.names:
                    self.used_names.add(alias.name)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    self.used_names.add(node.func.value.id)
            elif isinstance(node.func, ast.Name):
                self.used_names.add(node.func.id)
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            self.used_names.add(node.id)
            self.generic_visit(node)

    visitor = SecurityVisitor()
    visitor.visit(tree)

    all_modules = visitor.imports | visitor.used_names

    network_found = NETWORK_MODULES & all_modules
    high_risk_found = HIGH_RISK_MODULES & all_modules

    profile["needs_network_egress"] = bool(network_found)
    profile["high_risk"] = bool(high_risk_found)
    pip_found = PIP_MODULES & all_modules

    # Extract egress targets (URLs) for network policy
    egress_targets: list[dict[str, Any]] = []
    if network_found:
        egress_targets = _extract_urls_from_ast(tree)
    profile["egress_targets"] = egress_targets

    profile["findings"] = {
        "network_modules": sorted(network_found),
        "high_risk_modules": sorted(high_risk_found),
        "pip_modules": sorted(pip_found),
    }

    return profile

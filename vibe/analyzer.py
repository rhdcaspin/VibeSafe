"""AST-based code analysis for security profile extraction."""

import ast
from typing import Any


# Modules that indicate network egress is needed
NETWORK_MODULES = {"requests", "urllib", "http"}

# Modules that flag high risk (OS access, subprocess, etc.)
HIGH_RISK_MODULES = {"os", "sys", "subprocess"}

# Modules that require pip install (network + SPIRE/SPIFFE)
PIP_MODULES = NETWORK_MODULES | {"spiffe"}


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

    profile["findings"] = {
        "network_modules": sorted(network_found),
        "high_risk_modules": sorted(high_risk_found),
        "pip_modules": sorted(pip_found),
    }

    return profile

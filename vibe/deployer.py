"""Kubernetes deployment logic for applying generated manifests."""

import time
from typing import Any

import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.dynamic.client import DynamicClient


def _load_kubeconfig() -> None:
    """Load kubeconfig from default locations."""
    try:
        config.load_kube_config()
    except config.ConfigException:
        config.load_incluster_config()


def apply_manifests(yaml_strings: list[str]) -> None:
    """
    Parse YAML manifests and apply them to the active Kubernetes cluster.
    Uses DynamicClient for portability across kubernetes-client versions.
    """
    _load_kubeconfig()

    k8s_client = client.ApiClient()
    dynamic = DynamicClient(k8s_client)

    for yaml_content in yaml_strings:
        docs = yaml.safe_load_all(yaml_content)
        for doc in docs:
            if doc is None:
                continue
            _apply_resource(doc, dynamic)


def _apply_resource(manifest: dict[str, Any], dynamic: DynamicClient) -> None:
    """Apply a single manifest to the cluster using DynamicClient."""
    kind = manifest.get("kind", "")
    api_version = manifest.get("apiVersion", "v1")
    metadata = manifest.get("metadata", {})
    namespace = metadata.get("namespace", "default")

    # Cluster-scoped resources (no namespace)
    cluster_scoped = kind in (
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "Namespace",
    )

    resource = dynamic.resources.get(api_version=api_version, kind=kind)

    try:
        if cluster_scoped:
            resource.create(body=manifest)
        else:
            resource.create(body=manifest, namespace=namespace)
    except ApiException as e:
        if e.status == 409:  # Already exists - update or replace
            _apply_existing_resource(
                manifest, dynamic, kind, namespace, cluster_scoped
            )
        else:
            raise


def _apply_existing_resource(
    manifest: dict[str, Any],
    dynamic: DynamicClient,
    kind: str,
    namespace: str,
    cluster_scoped: bool,
) -> None:
    """Update existing resource. Pods must be deleted and recreated (spec is immutable)."""
    api_version = manifest.get("apiVersion", "v1")
    resource = dynamic.resources.get(api_version=api_version, kind=kind)
    name = manifest.get("metadata", {}).get("name", "")

    # Pods are immutable except for a few fields - delete and recreate to apply changes
    if kind == "Pod":
        dynamic.delete(resource, name=name, namespace=namespace)
        # Wait for pod to be fully removed before recreating
        for _ in range(30):
            try:
                dynamic.get(resource, name=name, namespace=namespace)
            except ApiException:
                break
            time.sleep(0.5)
        resource.create(body=manifest, namespace=namespace)
        return

    # Other resources: server-side apply
    if cluster_scoped:
        dynamic.server_side_apply(
            resource,
            body=manifest,
            field_manager="vibe-deploy",
            force_conflicts=True,
        )
    else:
        dynamic.server_side_apply(
            resource,
            body=manifest,
            namespace=namespace,
            field_manager="vibe-deploy",
            force_conflicts=True,
        )

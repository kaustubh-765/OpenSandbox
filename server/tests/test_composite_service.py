# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Create-time backend routing for the composite sandbox service."""

from __future__ import annotations

import asyncio

from opensandbox_server.api.schema import CreateSandboxRequest, ImageSpec, ResourceLimits
from opensandbox_server.services.composite_service import CompositeSandboxService


class _RecordingBackend:
    def __init__(self, name: str) -> None:
        self.name = name
        self.requests: list[CreateSandboxRequest] = []

    async def create_sandbox(self, request: CreateSandboxRequest) -> object:
        self.requests.append(request)
        return f"created-by-{self.name}"


def _create(*, snapshot_id: str | None = None, template_id: str | None = None) -> CreateSandboxRequest:
    if template_id is not None:
        # Template mode rejects every workload-shaping field by schema.
        return CreateSandboxRequest.model_construct(
            template_id=template_id,
            timeout=3600,
        )
    return CreateSandboxRequest.model_construct(
        image=None if snapshot_id else ImageSpec(uri="registry.example.com/app:1"),
        snapshot_id=snapshot_id,
        timeout=3600,
        entrypoint=None if snapshot_id else ["tail", "-f", "/dev/null"],
        resource_limits=ResourceLimits(root={"cpu": "500m", "memory": "512Mi"}),
    )


def _run(composite: CompositeSandboxService, request: CreateSandboxRequest) -> object:
    return asyncio.run(composite.create_sandbox(request))


class _PoolClient:
    def __init__(self, annotations: dict[str, str]) -> None:
        self.annotations = annotations
        self.reads = 0

    def get_custom_object(self, group, version, namespace, plural, name):
        self.reads += 1
        return {"metadata": {"name": name, "annotations": dict(self.annotations)}}


class _GoldenFsb(_RecordingBackend):
    def __init__(self, annotations: dict[str, str]) -> None:
        super().__init__("fsb")
        self.client = _PoolClient(annotations)

    def _kubernetes_client(self) -> _PoolClient:
        return self.client

    def _resolve_namespace(self) -> str:
        return "ns-1"


def _oci_create(cpu: str | None, memory: str | None, *, entrypoint=None, env=None) -> CreateSandboxRequest:
    limits = {k: v for k, v in (("cpu", cpu), ("memory", memory)) if v}
    return CreateSandboxRequest.model_construct(
        image=ImageSpec(uri="python:3.12"),
        timeout=600,
        entrypoint=entrypoint or ["tail", "-f", "/dev/null"],
        env=env,
        extensions={"poolRef": "osb-pool", "ociUser": "1000"},
        resource_limits=ResourceLimits(root=limits) if limits else None,
    )


def test_oci_create_picks_golden_by_size_and_carries_image() -> None:
    fsb = _GoldenFsb({
        "oci.fastsandbox.io/golden-template": "tpl-default",
        "oci.fastsandbox.io/golden-templates": '{"1/1Gi": "tpl-xs", "4/8192Mi": "tpl-l"}',
    })
    composite = CompositeSandboxService(kubernetes=_RecordingBackend("kubernetes"), fsb=fsb)  # type: ignore[arg-type]

    _run(composite, _oci_create("1000m", "1Gi", entrypoint=["python", "-V"], env={"A": "1"}))
    _run(composite, _oci_create("4", "8Gi"))
    _run(composite, _oci_create("2", "4Gi"))
    _run(composite, _oci_create(None, None))

    xs, large, unknown_size, unsized = fsb.requests
    assert xs.image.uri == "tpl-xs"
    assert xs.env["FSB_OCI_IMAGE"] == "python:3.12"
    assert xs.env["FSB_OCI_ENTRYPOINT"] == '["python", "-V"]'
    assert xs.env["FSB_OCI_ENV"] == '{"A": "1"}'
    assert xs.env["FSB_OCI_USER"] == "1000"
    assert "ociUser" not in xs.extensions
    assert xs.entrypoint == ["/usr/local/bin/ocirun", "agent"]
    assert large.image.uri == "tpl-l"
    assert unknown_size.image.uri == "tpl-default"
    assert unsized.image.uri == "tpl-default"
    # The pool annotations are cached between creates.
    assert fsb.client.reads == 1


def test_oci_create_ignores_invalid_sized_golden_annotation() -> None:
    fsb = _GoldenFsb({
        "oci.fastsandbox.io/golden-template": "tpl-default",
        "oci.fastsandbox.io/golden-templates": "not-json",
    })
    composite = CompositeSandboxService(kubernetes=_RecordingBackend("kubernetes"), fsb=fsb)  # type: ignore[arg-type]

    _run(composite, _oci_create("1", "1Gi"))

    assert fsb.requests[0].image.uri == "tpl-default"


def test_pool_without_golden_stays_with_pod_backend() -> None:
    kubernetes = _RecordingBackend("kubernetes")
    fsb = _GoldenFsb({})
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)  # type: ignore[arg-type]

    _run(composite, _oci_create("1", "2Gi"))

    assert kubernetes.requests and fsb.requests == []


def test_snapshot_restore_from_fsb_backend_routes_to_fsb() -> None:
    kubernetes = _RecordingBackend("kubernetes")
    fsb = _RecordingBackend("fsb")
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)  # type: ignore[arg-type]
    request = _create(snapshot_id="snap-1")
    request._resolved_snapshot_backend = "fsb"

    result = _run(composite, request)

    assert result == "created-by-fsb"
    assert fsb.requests and kubernetes.requests == []


def test_snapshot_restore_from_default_backend_stays_with_pod_backend() -> None:
    kubernetes = _RecordingBackend("kubernetes")
    fsb = _RecordingBackend("fsb")
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)  # type: ignore[arg-type]
    request = _create(snapshot_id="snap-2")
    request._resolved_snapshot_backend = None

    result = _run(composite, request)

    assert result == "created-by-kubernetes"
    assert kubernetes.requests and fsb.requests == []


def test_unresolved_snapshot_id_stays_with_pod_backend() -> None:
    kubernetes = _RecordingBackend("kubernetes")
    fsb = _RecordingBackend("fsb")
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)  # type: ignore[arg-type]
    request = _create(snapshot_id="snap-3")

    result = _run(composite, request)

    assert result == "created-by-kubernetes"
    assert kubernetes.requests and fsb.requests == []


def test_template_id_still_routes_to_fsb() -> None:
    kubernetes = _RecordingBackend("kubernetes")
    fsb = _RecordingBackend("fsb")
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)  # type: ignore[arg-type]

    result = _run(composite, _create(template_id="tpl-1"))

    assert result == "created-by-fsb"
    assert fsb.requests and kubernetes.requests == []


def test_list_sandboxes_passes_metadata_filter_to_kubernetes_backend() -> None:
    from unittest.mock import Mock
    from opensandbox_server.api.schema import (
        ListSandboxesRequest,
        PaginationRequest,
        SandboxFilter,
    )

    kubernetes = Mock()
    kubernetes.list_sandbox_objects.return_value = []
    fsb = Mock()
    fsb.list_sandbox_objects.return_value = []
    composite = CompositeSandboxService(kubernetes=kubernetes, fsb=fsb)

    request = ListSandboxesRequest(
        filter=SandboxFilter(metadata={"team": "infra"}),
        pagination=PaginationRequest(page=1, page_size=10),
    )
    composite.list_sandboxes(request)

    kubernetes.list_sandbox_objects.assert_called_once_with(metadata={"team": "infra"})
    fsb.list_sandbox_objects.assert_called_once_with()


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

import asyncio
import json
import logging
import os
import time

from fastapi import HTTPException

from opensandbox_server.api.schema import (
    CreateSandboxRequest,
    CreateSandboxResponse,
    Endpoint,
    ListSandboxesRequest,
    ListSandboxesResponse,
    NetworkPolicy,
    PatchSandboxMetadataRequest,
    RenewSandboxExpirationRequest,
    RenewSandboxExpirationResponse,
    Sandbox,
)
from opensandbox_server.services.diagnostics import DiagnosticContext, DiagnosticResult
from opensandbox_server.services.extension_service import ExtensionService
from opensandbox_server.services.fast_sandbox.create_mapping import canonical_size_key
from opensandbox_server.services.fast_sandbox.service import FastSandboxService
from opensandbox_server.services.k8s.kubernetes_service import KubernetesSandboxService
from opensandbox_server.services.k8s.list_helpers import _build_list_sandboxes_response
from opensandbox_server.services.sandbox_service import SandboxService

logger = logging.getLogger(__name__)

# Design 2 PoC: fast-sandbox pools whose golden template runs any OCI image
# from an attached image drive. The golden comes from the SandboxPool
# annotation oci.fastsandbox.io/golden-template (re-read every 30 s), else
# from OSB_OCI_DRIVE_POOLS="pool=tpl-id[,pool=tpl-id]". A create with image X
# on such a pool restores the golden template and carries X to the Fastlet
# in FSB_OCI_IMAGE; the launch overrides travel as FSB_OCI_ENTRYPOINT (JSON
# argv), FSB_OCI_ENV (JSON map), FSB_OCI_WORKDIR and FSB_OCI_USER.
OCI_DRIVE_IMAGE_ENV = "FSB_OCI_IMAGE"
OCI_DRIVE_ENTRYPOINT_ENV = "FSB_OCI_ENTRYPOINT"
OCI_DRIVE_ENV_ENV = "FSB_OCI_ENV"
OCI_DRIVE_WORKDIR_ENV = "FSB_OCI_WORKDIR"
OCI_DRIVE_USER_ENV = "FSB_OCI_USER"
OCI_DRIVE_ENTRYPOINT = ["/usr/local/bin/ocirun", "agent"]
# The OpenSandbox SDKs send this entrypoint when the caller sets none.
SDK_DEFAULT_ENTRYPOINT = ["tail", "-f", "/dev/null"]
# Extensions consumed here; the fsb backend only accepts poolRef.
OCI_DRIVE_EXTENSIONS = {"ociUser": OCI_DRIVE_USER_ENV, "ociWorkdir": OCI_DRIVE_WORKDIR_ENV}
GOLDEN_TEMPLATE_ANNOTATION = "oci.fastsandbox.io/golden-template"
# Per-size goldens for a ResourceAware pool: a JSON object whose keys are
# canonical "cpu/memory" sizes (e.g. {"1/1Gi": "tpl-a", "2/4Gi": "tpl-b"}).
# A create whose resourceLimits match a key restores that golden; otherwise
# the single golden-template annotation (the pool default size) is used.
GOLDEN_TEMPLATES_ANNOTATION = "oci.fastsandbox.io/golden-templates"
POOL_GROUP, POOL_VERSION, POOL_PLURAL = "sandbox.fast.io", "v1alpha2", "sandboxpools"
POOL_CACHE_SECONDS = 30.0


def _oci_drive_pools() -> dict[str, str]:
    pools: dict[str, str] = {}
    for entry in os.environ.get("OSB_OCI_DRIVE_POOLS", "").split(","):
        pool, _, template = entry.partition("=")
        if pool.strip() and template.strip():
            pools[pool.strip()] = template.strip()
    return pools


def _fsb_image_pools() -> set[str]:
    # Pools that take a plain OCI image directly (e.g. kata-fc), as "a,b".
    return {pool.strip() for pool in os.environ.get("OSB_FSB_IMAGE_POOLS", "").split(",") if pool.strip()}


def _with_oci_drive(request: CreateSandboxRequest, golden: str) -> CreateSandboxRequest:
    extensions = dict(request.extensions or {})
    env = dict(request.env or {})
    for key, env_key in OCI_DRIVE_EXTENSIONS.items():
        value = extensions.pop(key, None)
        if value is not None and str(value).strip():
            env[env_key] = str(value).strip()
    if request.image is None or not request.image.uri.strip() or request.image.uri.strip() == golden:
        return request.model_copy(update={"extensions": extensions, "env": env or request.env})
    env[OCI_DRIVE_IMAGE_ENV] = request.image.uri.strip()
    entrypoint = list(request.entrypoint or [])
    if entrypoint and entrypoint != SDK_DEFAULT_ENTRYPOINT and entrypoint != OCI_DRIVE_ENTRYPOINT:
        env[OCI_DRIVE_ENTRYPOINT_ENV] = json.dumps(entrypoint)
    user_env = {k: v for k, v in (request.env or {}).items() if v is not None and not k.startswith("FSB_OCI_")}
    if user_env:
        env[OCI_DRIVE_ENV_ENV] = json.dumps(user_env)
    return request.model_copy(update={
        "image": request.image.model_copy(update={"uri": golden}),
        "env": env,
        "extensions": extensions,
        "entrypoint": OCI_DRIVE_ENTRYPOINT,
    })


def _sized_goldens(pool_ref: str, raw: str | None) -> dict[str, str]:
    if not (raw or "").strip():
        return {}
    try:
        entries = json.loads(raw or "")
        if not isinstance(entries, dict):
            raise ValueError("not a JSON object")
        sized: dict[str, str] = {}
        for size, template in entries.items():
            cpu, _, memory = str(size).partition("/")
            if str(template).strip():
                sized[canonical_size_key(cpu, memory)] = str(template).strip()
        return sized
    except Exception as exc:
        logger.warning(f"Ignoring invalid {GOLDEN_TEMPLATES_ANNOTATION} on SandboxPool {pool_ref}: {exc}")
        return {}


def _size_key(request: CreateSandboxRequest) -> str | None:
    """Canonical "cpu/memory" of the request, or None without both limits."""
    limits = request.resource_limits.root if request.resource_limits is not None else {}
    cpu, memory = str(limits.get("cpu") or "").strip(), str(limits.get("memory") or "").strip()
    if not cpu or not memory:
        return None
    try:
        return canonical_size_key(cpu, memory)
    except Exception:
        return None


class CompositeSandboxService(SandboxService, ExtensionService):
    def __init__(self, kubernetes: KubernetesSandboxService, fsb: FastSandboxService):
        self._kubernetes = kubernetes
        self._fsb = fsb
        self._pool_goldens: dict[str, tuple[float, str | None, dict[str, str]]] = {}

    @property
    def fsb_service(self) -> FastSandboxService:
        """The fsb backend, for background integrations."""
        return self._fsb

    def _annotated_golden(self, pool_ref: str) -> tuple[str | None, dict[str, str]]:
        """Read the pool's default golden and its per-size goldens.

        A missing pool, a pool without the annotations, or an API error all
        mean "no annotation"; the env mapping then decides.
        """
        try:
            pool = self._fsb._kubernetes_client().get_custom_object(
                POOL_GROUP, POOL_VERSION, self._fsb._resolve_namespace(), POOL_PLURAL, pool_ref
            )
        except Exception as exc:
            logger.warning(f"Cannot read SandboxPool {pool_ref}: {exc}")
            return None, {}
        annotations = ((pool or {}).get("metadata") or {}).get("annotations") or {}
        default = (annotations.get(GOLDEN_TEMPLATE_ANNOTATION) or "").strip() or None
        return default, _sized_goldens(pool_ref, annotations.get(GOLDEN_TEMPLATES_ANNOTATION))

    async def _golden_for_pool(self, pool_ref: str, size_key: str | None = None) -> str | None:
        cached = self._pool_goldens.get(pool_ref)
        if cached is None or time.monotonic() - cached[0] > POOL_CACHE_SECONDS:
            default, sized = await asyncio.to_thread(self._annotated_golden, pool_ref)
            cached = (time.monotonic(), default, sized)
            self._pool_goldens[pool_ref] = cached
        if size_key and size_key in cached[2]:
            return cached[2][size_key]
        return cached[1] or _oci_drive_pools().get(pool_ref)

    def _backend(self, sandbox_id: str) -> KubernetesSandboxService | FastSandboxService:
        return self._fsb if sandbox_id.startswith("fsb-") else self._kubernetes

    def set_tenant_provider(self, provider: object) -> None:
        self._kubernetes.set_tenant_provider(provider)
        self._fsb.set_tenant_provider(provider)

    def close(self) -> None:
        self._fsb.close()
        self._kubernetes.close()

    async def create_sandbox(self, request: CreateSandboxRequest) -> CreateSandboxResponse:
        # templateId is the unambiguous fsb selector: fsb sandboxes are
        # the microVM catalog and coexist with the container-sandbox
        # workload provider. A snapshotId resolved to an fsb-produced
        # artifact (restore_config.backend == "fsb") selects fsb the same
        # way; every other create stays with it.
        if (request.template_id or "").strip():
            return await self._fsb.create_sandbox(request)
        if (request.snapshot_id or "").strip() and request.resolved_snapshot_backend == "fsb":
            return await self._fsb.create_sandbox(request)
        # Only the configured OCI-drive pools route here; every other poolRef
        # (including OpenSandbox pod pools) keeps its previous backend.
        pool_ref = str((request.extensions or {}).get("poolRef") or "").strip()
        golden = await self._golden_for_pool(pool_ref, _size_key(request)) if pool_ref else None
        if golden:
            return await self._fsb.create_sandbox(_with_oci_drive(request, golden))
        if pool_ref and pool_ref in _fsb_image_pools():
            return await self._fsb.create_sandbox(request)
        return await self._kubernetes.create_sandbox(request)

    def list_sandboxes(self, request: ListSandboxesRequest) -> ListSandboxesResponse:
        try:
            metadata = request.filter.metadata if request.filter else None
            objects = self._kubernetes.list_sandbox_objects(metadata=metadata) + self._fsb.list_sandbox_objects()
            objects.sort(key=lambda sandbox: sandbox.id)
            return _build_list_sandboxes_response(objects, request)
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"Cannot read complete sandbox list: {exc}")
            raise HTTPException(
                503,
                detail={
                    "code": "SANDBOX_LIST_UNAVAILABLE",
                    "message": "Cannot read the complete sandbox list.",
                },
            ) from exc

    def get_sandbox(self, sandbox_id: str) -> Sandbox:
        return self._backend(sandbox_id).get_sandbox(sandbox_id)

    def patch_sandbox_metadata(
        self, sandbox_id: str, patch: PatchSandboxMetadataRequest
    ) -> Sandbox:
        return self._backend(sandbox_id).patch_sandbox_metadata(sandbox_id, patch)

    def delete_sandbox(self, sandbox_id: str) -> None:
        self._backend(sandbox_id).delete_sandbox(sandbox_id)

    def pause_sandbox(self, sandbox_id: str) -> None:
        self._backend(sandbox_id).pause_sandbox(sandbox_id)

    def resume_sandbox(self, sandbox_id: str) -> None:
        self._backend(sandbox_id).resume_sandbox(sandbox_id)

    def renew_expiration(
        self, sandbox_id: str, request: RenewSandboxExpirationRequest
    ) -> RenewSandboxExpirationResponse:
        return self._backend(sandbox_id).renew_expiration(sandbox_id, request)

    def get_endpoint(
        self,
        sandbox_id: str,
        port: int,
        resolve_internal: bool = False,
        expires: int | None = None,
        use_proxy_host: bool = False,
    ) -> Endpoint:
        return self._backend(sandbox_id).get_endpoint(
            sandbox_id, port, resolve_internal, expires, use_proxy_host
        )

    def get_access_renew_extend_seconds(self, sandbox_id: str) -> int | None:
        return self._backend(sandbox_id).get_access_renew_extend_seconds(sandbox_id)

    def get_network_policy(self, sandbox_id: str) -> dict:
        return self._fsb.get_network_policy(sandbox_id)

    def replace_network_policy(self, sandbox_id: str, policy: NetworkPolicy) -> dict:
        return self._fsb.replace_network_policy(sandbox_id, policy)

    def patch_network_policy(self, sandbox_id: str, rules: list) -> dict:
        return self._fsb.patch_network_policy(sandbox_id, rules)

    def delete_network_policy_rules(self, sandbox_id: str, targets: list) -> dict:
        return self._fsb.delete_network_policy_rules(sandbox_id, targets)

    # -- credential vault (fsb relay only, OSEP-0022) -----------------------

    def create_credential_vault(self, sandbox_id: str, request) -> dict:
        return self._fsb.create_credential_vault(sandbox_id, request)

    def get_credential_vault(self, sandbox_id: str) -> dict:
        return self._fsb.get_credential_vault(sandbox_id)

    def patch_credential_vault(self, sandbox_id: str, request) -> dict:
        return self._fsb.patch_credential_vault(sandbox_id, request)

    def delete_credential_vault(self, sandbox_id: str) -> None:
        self._fsb.delete_credential_vault(sandbox_id)

    def list_credential_vault_credentials(self, sandbox_id: str) -> dict:
        return self._fsb.list_credential_vault_credentials(sandbox_id)

    def get_credential_vault_credential(self, sandbox_id: str, name: str) -> dict:
        return self._fsb.get_credential_vault_credential(sandbox_id, name)

    def list_credential_vault_bindings(self, sandbox_id: str) -> dict:
        return self._fsb.list_credential_vault_bindings(sandbox_id)

    def get_credential_vault_binding(self, sandbox_id: str, name: str) -> dict:
        return self._fsb.get_credential_vault_binding(sandbox_id, name)

    def get_sandbox_log_diagnostics(self, sandbox_id: str, scope: str) -> DiagnosticResult:
        return self._backend(sandbox_id).get_sandbox_log_diagnostics(sandbox_id, scope)

    def get_sandbox_diagnostic_context(self, sandbox_id: str) -> DiagnosticContext:
        return self._backend(sandbox_id).get_sandbox_diagnostic_context(sandbox_id)

    def get_sandbox_event_diagnostics(self, sandbox_id: str, scope: str) -> DiagnosticResult:
        return self._backend(sandbox_id).get_sandbox_event_diagnostics(sandbox_id, scope)

    def get_sandbox_logs(
        self,
        sandbox_id: str,
        tail: int = 100,
        since: str | None = None,
        container: str | None = None,
    ) -> str:
        return self._backend(sandbox_id).get_sandbox_logs(sandbox_id, tail, since, container)

    def get_sandbox_inspect(self, sandbox_id: str) -> str:
        return self._backend(sandbox_id).get_sandbox_inspect(sandbox_id)

    def get_sandbox_events(self, sandbox_id: str, limit: int = 50) -> str:
        return self._backend(sandbox_id).get_sandbox_events(sandbox_id, limit)

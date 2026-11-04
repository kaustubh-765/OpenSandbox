# pyright: reportAttributeAccessIssue=false
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

import json

from opensandbox_server.api.schema import ImageSpec, Sandbox, SandboxStatus
from opensandbox_server.services.fast_sandbox.generated import fastpath_pb2 as pb2
from opensandbox_server.services.fast_sandbox.status_mapping import map_reason, map_state

METADATA_PREFIX = "metadata.sandbox.fast.io/"


def sandbox_from_cr(cr: dict) -> Sandbox:
    metadata, spec = cr["metadata"], cr["spec"]
    observed = cr.get("status") or {}
    runtime = observed.get("runtime") or {}
    data_plane = observed.get("dataPlane") or {}
    generation = metadata.get("generation", 1)
    condition = next((c for c in observed.get("conditions", []) if c.get("type") == "Ready"), {})
    info = pb2.SandboxInfo(
        runtime=pb2.RuntimeInfo(
            state=getattr(pb2, "RUNTIME_STATE_" + runtime.get("state", "Unknown").upper(), 0)
        ),
        data_plane=pb2.DataPlaneInfo(
            state=getattr(pb2, "DATA_PLANE_STATE_" + data_plane.get("state", "Unknown").upper(), 0)
        ),
        infra_components=[
            pb2.InfraComponentInfo(
                state=getattr(pb2, "INFRA_COMPONENT_STATE_" + c.get("state", "").upper(), 0)
            )
            for c in observed.get("infraComponents", [])
        ],
        action_bindings=[
            pb2.ActionBindingInfo(
                state=getattr(pb2, "ACTION_STATE_" + b.get("state", "").upper(), 0)
            )
            for b in observed.get("actionBindings", [])
        ],
        ready=(
            condition.get("status") == "True"
            and condition.get("observedGeneration", 0) >= generation
            and observed.get("observedGeneration", 0) >= generation
            and runtime.get("state") == "Ready"
            and data_plane.get("state") == "Ready"
        ),
    )
    state = map_state(info)
    if metadata.get("deletionTimestamp") and state not in ("Terminated", "Failed"):
        state = "Stopping"
    # Design 2 PoC: an OCI-drive Sandbox runs the golden template; report the
    # customer image and entrypoint it carries instead.
    envs = {e.get("name"): e.get("value") for e in spec.get("envs") or [] if isinstance(e, dict)}
    entrypoint = list(spec.get("command") or []) + list(spec.get("args") or [])
    if envs.get("FSB_OCI_ENTRYPOINT"):
        try:
            override = json.loads(str(envs["FSB_OCI_ENTRYPOINT"]))
            if isinstance(override, list) and all(isinstance(a, str) for a in override):
                entrypoint = override
        except ValueError:
            pass
    return Sandbox(
        id=metadata["name"],
        image=ImageSpec(uri=envs.get("FSB_OCI_IMAGE") or spec["image"], auth=None),
        snapshotId=None,
        platform=None,
        allocation=None,
        entrypoint=entrypoint,
        metadata={
            key.removeprefix(METADATA_PREFIX): value
            for key, value in (metadata.get("labels") or {}).items()
            if key.startswith(METADATA_PREFIX)
        },
        extensions={"poolRef": spec["poolRef"]},
        createdAt=metadata["creationTimestamp"],
        expiresAt=spec.get("expireTime"),
        status=SandboxStatus(
            state=state,
            reason=condition.get("reason") or map_reason(info),
            message=condition.get("message") or runtime.get("message"),
            lastTransitionAt=condition.get("lastTransitionTime")
            or runtime.get("lastTransitionTime"),
        ),
    )

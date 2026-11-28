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

from pathlib import Path
import shutil
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
HELM = shutil.which("helm")
CHECKSUM = "fast-sandbox.io/transfer-checksum"


@unittest.skipUnless(HELM, "helm is required")
class FastSandboxTransferChartTest(unittest.TestCase):
    def run_helm(self, chart, *values):
        command = [HELM, "template", "test", str(ROOT / "manifests/charts" / chart)]
        for value in values:
            command.extend(["--set", value])
        return subprocess.run(command, capture_output=True, text=True)

    def render(self, *values):
        result = self.run_helm("fast-sandbox", *values)
        self.assertEqual(result.returncode, 0, result.stderr)
        resources = [x for x in yaml.safe_load_all(result.stdout) if x]
        config = next(
            x
            for x in resources
            if x["kind"] == "ConfigMap"
            and x["metadata"]["name"] == "fast-sandbox-firecracker-runtime-config"
        )
        daemonset = next(
            x
            for x in resources
            if x["kind"] == "DaemonSet" and x["metadata"]["name"] == "firecracker-runtime"
        )
        agent = yaml.safe_load(config["data"]["agent.yaml"])
        annotations = daemonset["spec"]["template"]["metadata"]["annotations"]
        return agent, annotations

    def assert_fails(self, message, *values):
        result = self.run_helm("fast-sandbox", *values)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_defaults_render_no_transfer_section(self):
        for values in ([], ["runtime.transfer=null"], ["runtime.transfer.format=legacy"]):
            agent, annotations = self.render(*values)
            self.assertNotIn("transfer", agent)
            self.assertNotIn(CHECKSUM, annotations)

    def test_chunked_renders_full_section_and_checksum(self):
        agent, annotations = self.render("runtime.transfer.format=chunked")
        self.assertEqual(
            agent["transfer"],
            {
                "format": "chunked",
                "compression": "none",
                "concurrency": 8,
                "chunkSizeMiB": 4,
                "chunkListOnly": False,
            },
        )
        self.assertIn(CHECKSUM, annotations)

    def test_any_setting_change_changes_checksum(self):
        base = ["runtime.transfer.format=chunked"]
        _, chunked = self.render(*base)
        agent, all_set = self.render(
            *base,
            "runtime.transfer.compression=zstd",
            "runtime.transfer.chunkListOnly=true",
            "runtime.transfer.concurrency=16",
            "runtime.transfer.chunkSizeMiB=8",
        )
        self.assertEqual(
            agent["transfer"],
            {
                "format": "chunked",
                "compression": "zstd",
                "concurrency": 16,
                "chunkSizeMiB": 8,
                "chunkListOnly": True,
            },
        )
        self.assertNotEqual(chunked[CHECKSUM], all_set[CHECKSUM])
        _, again = self.render(*base)
        self.assertEqual(chunked[CHECKSUM], again[CHECKSUM])

    def test_non_default_legacy_setting_renders_section(self):
        agent, annotations = self.render("runtime.transfer.concurrency=16")
        self.assertEqual(agent["transfer"]["format"], "legacy")
        self.assertEqual(agent["transfer"]["concurrency"], 16)
        self.assertIn(CHECKSUM, annotations)

    def test_custom_config_ignores_transfer(self):
        agent, annotations = self.render(
            "runtime.config=socket: /run/x.sock",
            "runtime.transfer.format=chunked",
        )
        self.assertEqual(agent, {"socket": "/run/x.sock"})
        self.assertNotIn(CHECKSUM, annotations)

    def test_invalid_settings_fail_render(self):
        self.assert_fails(
            "requires runtime.transfer.format=chunked",
            "runtime.transfer.compression=zstd",
        )
        self.assert_fails(
            "requires runtime.transfer.format=chunked",
            "runtime.transfer.chunkListOnly=true",
        )
        self.assert_fails("must be legacy or chunked", "runtime.transfer.format=fast")
        self.assert_fails(
            "must be none or zstd",
            "runtime.transfer.format=chunked",
            "runtime.transfer.compression=gzip",
        )
        self.assert_fails("must be a positive integer", "runtime.transfer.concurrency=0")
        self.assert_fails("must be a positive integer", "runtime.transfer.chunkSizeMiB=1.5")
        self.assert_fails("not a known key", "runtime.transfer.chunkSize=4")


if __name__ == "__main__":
    unittest.main()

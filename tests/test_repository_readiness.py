from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RepositoryReadinessTests(unittest.TestCase):
    def test_validator_passes(self) -> None:
        subprocess.run(
            ["python3", "scripts/validate_repository_readiness.py"],
            cwd=ROOT,
            check=True,
        )

    def test_bundle_is_deterministic_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outputs = [Path(directory) / name for name in ("one.tar.gz", "two.tar.gz")]
            for output in outputs:
                subprocess.run(
                    ["python3", "scripts/build_config_bundle.py", "--output", str(output)],
                    cwd=ROOT,
                    check=True,
                )
            self.assertEqual(
                hashlib.sha256(outputs[0].read_bytes()).digest(),
                hashlib.sha256(outputs[1].read_bytes()).digest(),
            )
            manifest = json.loads(
                (ROOT / "codestra/release/config-bundle.manifest.json").read_text()
            )
            with tarfile.open(outputs[0], "r:gz") as archive:
                names = set(archive.getnames())
            self.assertEqual(
                names,
                set(manifest["files"]) | {"codestra/release/config-bundle.manifest.json"},
            )

    def test_runtime_image_is_fixed_and_private(self) -> None:
        compose = (ROOT / "deploy/compose.yaml").read_text()
        lock = json.loads((ROOT / "codestra/release/runtime-image.lock.json").read_text())
        self.assertIn(f"image: {lock['image']}", compose)
        self.assertNotIn("POSTGRES_EXPORTER_IMAGE", compose)
        self.assertNotIn("\n    ports:\n", compose)

    def test_release_job_is_structurally_pinned(self) -> None:
        import yaml

        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release-config-bundle.yml").read_text()
        )
        job = workflow["jobs"]["release"]
        self.assertEqual(
            job["uses"],
            "appolon1908-hue/Codestra-Telemetry/.github/workflows/"
            "reusable-release-config-bundle.yml@"
            "777292781faeca9348d0e2ecdce6ac3f50c91d93",
        )
        self.assertEqual(job["with"]["component_id"], "postgres-exporter")


if __name__ == "__main__":
    unittest.main()

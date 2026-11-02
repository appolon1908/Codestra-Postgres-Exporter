"""Execute the workflow's integrity checks against real disposable commits."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/required-exact-sha-ci.yml"


class ExactSourceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.base = self.commit("clean baseline\n")
        self.document = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        self.job = self.document["jobs"]["exact-sha"]

    def git(self, *arguments):
        result = subprocess.run(
            ["git", "-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid", *arguments],
            cwd=self.repository, text=True, capture_output=True, check=True,
        )
        return result.stdout.strip()

    def commit(self, content):
        (self.repository / "source.txt").write_text(content)
        self.git("add", "source.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def verify(self, *, event="pull_request", target=None, base=None):
        environment = {
            "PATH": os.environ["PATH"],
            "GITHUB_EVENT_NAME": event,
            "EXPECTED_SHA": target or self.git("rev-parse", "HEAD"),
            "BASE_SHA": self.base if base is None else base,
        }
        for step in self.job["steps"]:
            if step.get("name") not in {
                "Prove exact checkout", "Reject merge, rebase, or cherry-pick residue",
                "Validate repository integrity",
            }:
                continue
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step["run"]],
                cwd=self.repository, env=environment, text=True, capture_output=True,
            )
            if result.returncode:
                return result
        return result

    def test_untrusted_pull_requests_use_hosted_read_only_execution(self):
        self.assertIn("pull_request", self.document["on"])
        self.assertIsInstance(self.job["runs-on"], str)
        self.assertNotIn("self-hosted", self.job["runs-on"])
        self.assertEqual(self.document["permissions"], {"contents": "read"})

    def test_clean_candidate_passes(self):
        self.commit("clean candidate\n")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_committed_whitespace_fails_even_with_clean_checkout(self):
        self.commit("trailing whitespace   \n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_or_unknown_pr_base_fails(self):
        self.commit("clean candidate\n")
        for base in ("", "0" * 40):
            with self.subTest(base=base):
                self.assertNotEqual(self.verify(base=base).returncode, 0)

    def test_wrong_or_symbolic_target_fails(self):
        self.commit("clean candidate\n")
        for target in (self.base, "HEAD"):
            with self.subTest(target=target):
                self.assertNotEqual(self.verify(target=target).returncode, 0)

    def test_dispatch_checks_candidate_against_its_parent(self):
        self.commit("trailing whitespace   \n")
        self.assertNotEqual(self.verify(event="workflow_dispatch", base="").returncode, 0)

    def test_dispatch_can_validate_a_clean_initial_commit(self):
        result = self.verify(event="workflow_dispatch", base="")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unexpected_event_fails_closed(self):
        self.commit("clean candidate\n")
        self.assertNotEqual(self.verify(event="push").returncode, 0)


if __name__ == "__main__":
    unittest.main()

"""Prove Dependabot manifest edits propagate to CI action inputs."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("ci-versions.sh").resolve()


class VersionsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "tools").mkdir()

    def run_versions(self, go="1.27.3", trivy="0.76.0", goreleaser="v2.18.3"):
        (self.root / "Dockerfile").write_text(
            f"FROM --platform=$BUILDPLATFORM golang:{go} AS build\n"
        )
        (self.root / "tools/compose.yml").write_text(
            f"services:\n  trivy:\n    image: aquasec/trivy:{trivy}\n"
            f"  goreleaser:\n    image: goreleaser/goreleaser:{goreleaser}\n"
        )
        return subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.root, capture_output=True, text=True
        )

    def test_dependabot_image_updates_propagate(self):
        result = self.run_versions(go="1.27.4", trivy="0.77.0", goreleaser="v2.19.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "go=1.27.4\ntrivy=v0.77.0\ngoreleaser=v2.19.0\n"
        )

    def test_reject_unpinned_versions(self):
        for versions in ({"go": "latest"}, {"trivy": "latest"}, {"goreleaser": "latest"}):
            with self.subTest(versions=versions):
                result = self.run_versions(**versions)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_reject_workflow_output_injection(self):
        result = self.run_versions(goreleaser="v2.18.3\n    image: goreleaser/goreleaser:v9.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

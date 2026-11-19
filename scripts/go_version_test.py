"""Prove Docker toolchain updates propagate without changing go.mod."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("go-version.sh")


class GoVersionTest(unittest.TestCase):
    def read_version(self, dockerfile):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "Dockerfile").write_text(dockerfile)
            # The module minimum intentionally stays behind the Docker toolchain.
            Path(directory, "go.mod").write_text("module example.com/test\n\ngo 1.27.3\n")
            return subprocess.run(
                ["bash", str(SCRIPT)], cwd=directory, capture_output=True, text=True
            )

    def test_follows_docker_updates_instead_of_module_minimum(self):
        for version in ("1.27.4", "1.27.5", "1.28.1"):
            with self.subTest(version=version):
                result = self.read_version(
                    f"FROM --platform=$BUILDPLATFORM golang:{version} AS build\n"
                    "FROM gcr.io/distroless/static-debian12:nonroot\n"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"go={version}\n")

    def test_rejects_missing_builder(self):
        result = self.read_version("FROM scratch\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_rejects_unpinned_builder(self):
        for version in ("latest", "1.27", "1.27.4;echo unsafe"):
            with self.subTest(version=version):
                result = self.read_version(
                    f"FROM --platform=$BUILDPLATFORM golang:{version} AS build\n"
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_rejects_ambiguous_builders(self):
        result = self.read_version(
            "FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build\n"
            "FROM --platform=$BUILDPLATFORM golang:1.27.5 AS build\n"
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

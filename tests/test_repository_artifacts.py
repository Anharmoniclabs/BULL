"""Keep locally built VM assets out of the Git index (no VM boot required)."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BEGIN = "# BEGIN LOCAL-ONLY MICROVM ARTIFACTS"
END = "# END LOCAL-ONLY MICROVM ARTIFACTS"


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


class RepositoryArtifactPolicy(unittest.TestCase):
    def test_no_tracked_local_assets(self):
        """Check the index, including artifacts added with git add --force."""
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertEqual(text.count(BEGIN), 1)
        self.assertEqual(text.count(END), 1)
        policy = text.split(BEGIN, 1)[1].split(END, 1)[0]
        self.assertTrue(policy.strip(), "Local-artifact policy must not be empty")
        with tempfile.TemporaryDirectory(prefix="bull-artifact-policy-") as tmp:
            excludes = Path(tmp) / "exclude"
            excludes.write_text(policy, encoding="utf-8")
            tracked = git(
                ROOT, "ls-files", "--cached", "--ignored",
                f"--exclude-from={excludes}", "-z",
            )
        names = [name.decode("utf-8", "backslashreplace")
                 for name in tracked.split(b"\0") if name]
        self.assertEqual(
            names, [],
            "Local-only VM assets are tracked. Untrack them while preserving "
            "local copies; review history separately. Paths: " + repr(names),
        )

    def test_images_and_private_deployment_files_are_ignored(self):
        samples = [
            "rootfs.ext4", "nested/guest.ext4.gz", "disk.ext2", "disk.ext3",
            "disk.qcow", "disk.qcow2", "disk.qcow2.xz", "disk.img",
            "disk.img.gz", "disk.raw", "disk.raw.zst", "disk.vhd",
            "disk.vhdx", "disk.vmdk", "disk.vdi", "disk.iso",
            "assets/vmlinux", "assets/vmlinuz-test", "assets/bzImage",
            "assets/initramfs.img", "assets/initrd.img",
            "microvm/assets/guest.bin", "microvm/images/workspace.bin",
            "microvm/local/state", "microvm/rootfs-tree/etc/passwd",
            "microvm/config/deployment.env", "microvm/config/dev.local.env",
            "deployment.env", "nested/image with spaces.ext4",
        ]
        with tempfile.TemporaryDirectory(prefix="bull-ignore-test-") as tmp:
            root = Path(tmp)
            git(root, "init", "--quiet")
            shutil.copyfile(ROOT / ".gitignore", root / ".gitignore")
            actual = git(
                root, "check-ignore", "--no-index", "--stdin", "-z",
                data=b"\0".join(s.encode() for s in samples) + b"\0",
            )
        self.assertEqual(
            set(actual.rstrip(b"\0").split(b"\0")),
            {s.encode() for s in samples},
        )

    def test_source_and_templates_remain_trackable(self):
        samples = [
            "microvm/rootfs/build-ext4.sh", "microvm/run-bull-microvm.sh",
            "microvm/guest/init", "microvm/config/defaults.env",
            "microvm/README.md", "src/bulldog/microvm.py",
            "site/assets/logo.svg", "tests/test_repository_artifacts.py",
        ]
        with tempfile.TemporaryDirectory(prefix="bull-source-test-") as tmp:
            root = Path(tmp)
            git(root, "init", "--quiet")
            shutil.copyfile(ROOT / ".gitignore", root / ".gitignore")
            result = subprocess.run(
                ["git", "-C", str(root), "check-ignore", "--no-index",
                 "--stdin", "-z"],
                input=b"\0".join(s.encode() for s in samples) + b"\0",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_templates_do_not_embed_machine_specific_deployment_root(self):
        private_root = "/srv/" + "bull/"
        for name in ("microvm/README.md", "microvm/config/defaults.env"):
            with self.subTest(path=name):
                self.assertNotIn(
                    private_root, (ROOT / name).read_text(encoding="utf-8"),
                )


if __name__ == "__main__":
    unittest.main()

"""The TruffleHog scan container's writable scratch.

The container runs as a non-root uid with a READ-ONLY root filesystem, so every
byte it writes goes to a tmpfs supplied at spawn. One of those tmpfs mounts is
the scan user's HOME, and it is the subtle one: Docker mounts a tmpfs root-owned
0755 unless told otherwise, and the mount SHADOWS the home directory the image
built with `useradd --create-home`. Get it wrong and the directory the image
prepared for uid 10001 is replaced, at runtime, by one only root can write.

That is not a hypothetical. It broke `github_experimental` and nothing else:
object discovery caches repository objects under ~/.trufflehog, so it was the
only source that ever touched $HOME, and the failure surfaced as
"fatal: failed to create .trufflehog folder in user's home directory" - which
reads like a scanner bug rather than a mount bug.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from container_manager import (  # noqa: E402
    ContainerManager, TRUFFLEHOG_CONTAINER_USER, TRUFFLEHOG_CONTAINER_UID,
)


@pytest.fixture
def manager():
    with patch('container_manager.docker') as mock_docker_mod:
        mock_docker_mod.from_env.return_value = MagicMock()
        mgr = ContainerManager()
        mgr.client = MagicMock()
        return mgr


class TestTrufflehogTmpfs:
    def test_the_scan_user_home_is_a_tmpfs(self, manager):
        # The image's own /home/<user> is on the read-only root, so without this
        # entry there is nowhere for the scan uid to write a dotfile at all.
        assert f"/home/{TRUFFLEHOG_CONTAINER_USER}" in manager._trufflehog_tmpfs()

    def test_the_home_tmpfs_is_owned_by_the_scan_uid(self, manager):
        opts = manager._trufflehog_tmpfs()[f"/home/{TRUFFLEHOG_CONTAINER_USER}"]
        parts = dict(p.split("=", 1) for p in opts.split(",") if "=" in p)
        # Both halves matter: a uid without a gid still leaves the group root,
        # and Docker's unset default is root:root 0755.
        assert parts.get("uid") == str(TRUFFLEHOG_CONTAINER_UID)
        assert parts.get("gid") == str(TRUFFLEHOG_CONTAINER_UID)
        assert "mode" in parts, "an unset mode is Docker's root-owned 0755"

    def test_the_home_tmpfs_is_not_world_writable(self, manager):
        # 1777 would also work, and is what /tmp gets by default. It is not what
        # this mount should be: the home directory has exactly one legitimate
        # writer, and the container parses attacker-controlled bytes.
        opts = manager._trufflehog_tmpfs()[f"/home/{TRUFFLEHOG_CONTAINER_USER}"]
        parts = dict(p.split("=", 1) for p in opts.split(",") if "=" in p)
        mode = int(parts["mode"], 8)
        assert not mode & 0o007, f"mode {parts['mode']} grants other-access"

    def test_tmp_stays_executable_scratch(self, manager):
        # Archive extraction and the git helper both run out of /tmp; a tmpfs
        # mounted noexec (Docker's default) breaks them.
        assert "exec" in manager._trufflehog_tmpfs()["/tmp"].split(",")

    def test_every_tmpfs_entry_is_size_capped(self, manager):
        # A tmpfs is host RAM. An uncapped one lets a hostile target exhaust the
        # host by handing the scanner an endlessly inflating archive.
        for path, opts in manager._trufflehog_tmpfs().items():
            assert any(o.startswith("size=") for o in opts.split(",")), path

    def test_the_user_matches_the_image(self, manager):
        # The constant is the spawn's copy of the Dockerfile's
        # `useradd --uid 10001 ... trufflehog`. If the image's user moves and
        # this does not, the home tmpfs is handed to a uid that no longer exists
        # and the scan user is locked out of its home again.
        dockerfile = (Path(__file__).resolve().parents[1]
                      / "scanners" / "trufflehog_scan" / "Dockerfile")
        if not dockerfile.is_file():
            pytest.skip(f"{dockerfile} is not mounted into this test image")
        text = dockerfile.read_text()
        assert f"--uid {TRUFFLEHOG_CONTAINER_UID}" in text
        assert f"{TRUFFLEHOG_CONTAINER_USER} &&" in text or \
               f" {TRUFFLEHOG_CONTAINER_USER}\n" in text

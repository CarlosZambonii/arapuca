"""The fake filesystem the page walks, and the guard that keeps it honest."""

import json
import pathlib

import shell_export

REPO = pathlib.Path(__file__).resolve().parents[2]


def _tree():
    return {
        "root": {
            "etc": {
                "type": "dir",
                "children": {
                    "hostname": {"type": "file", "content": "srv-web-03\n"},
                    "shadow": {
                        "type": "file",
                        "mode": "-rw-r-----",
                        "group": "shadow",
                        "content": "root:!:19000:0:99999:7:::\n",
                    },
                },
            },
            "tmp": {"type": "dir", "mode": "drwxrwxrwt"},
        }
    }


def test_build_flattens_the_tree_to_absolute_paths():
    files = shell_export.build(_tree())["files"]
    assert set(files) == {"/", "/etc", "/etc/hostname", "/etc/shadow", "/tmp"}
    assert files["/etc/hostname"]["content"] == "srv-web-03\n"
    assert files["/etc/hostname"]["size"] == len("srv-web-03\n")


def test_build_lists_children_in_order():
    files = shell_export.build(_tree())["files"]
    assert files["/"]["children"] == ["etc", "tmp"]
    assert files["/etc"]["children"] == ["hostname", "shadow"]


def test_build_applies_the_same_defaults_as_the_daemon():
    # include/arapuca/ssh/vfs.hpp: root:root, a fixed mtime, and the mode a
    # node gets when it does not say.
    files = shell_export.build(_tree())["files"]
    assert files["/etc"]["mode"] == shell_export.DIR_MODE
    assert files["/etc/hostname"]["mode"] == shell_export.FILE_MODE
    assert files["/tmp"]["mode"] == "drwxrwxrwt"  # the node's own
    assert files["/etc/shadow"]["group"] == "shadow"
    assert files["/etc/hostname"]["owner"] == "root"
    assert files["/etc/hostname"]["mtime"] == shell_export.DEFAULT_MTIME


def test_build_truncates_a_file_too_large_for_a_phone():
    tree = {"root": {"big": {"type": "file", "content": "x" * (shell_export.MAX_FILE_BYTES + 50)}}}
    entry = shell_export.build(tree)["files"]["/big"]
    assert entry["content"].endswith(shell_export.TRUNCATION_NOTE)
    ceiling = shell_export.MAX_FILE_BYTES + len(shell_export.TRUNCATION_NOTE)
    assert len(entry["content"]) <= ceiling


def test_the_committed_export_matches_the_filesystem_the_daemon_loads():
    """The page claims its terminal answers what the honeypot would answer.

    That is only true while web/data/shell.json is what config/filesystem.yaml
    says. Regenerate with `python tools/shell_export.py` when this fails.
    """
    yaml = __import__("yaml")
    source = REPO / "config" / "filesystem.yaml"
    committed = REPO / "web" / "data" / "shell.json"

    expected = shell_export.build(yaml.safe_load(source.read_text(encoding="utf-8")))
    actual = json.loads(committed.read_text(encoding="utf-8"))
    assert actual == expected

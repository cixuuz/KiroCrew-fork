"""The release-channel populate's private git common dir is out of every agent's reach.

The populate reads config from a throwaway common dir instead of the repository's own
``.git/config``. That dir is created under ``<data home>/run`` -- withheld from
sandboxed children -- and never in the worktree parent every agent shares, where a
same-user writer could plant a ``filter.<name>.smudge`` driver in its ``config``
between the ``mkdtemp`` and the ``read-tree`` that runs it.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest
from git_maintenance_helpers import git_maintenance_off_entries
from test_dev_fleet_release_channel_ops import (  # noqa: F401  # fixtures are used by name
    _fixture_git_env,
    _Git,
    _isolated_fleet_epochs,
    _spawn,
    repo,
    requires_git,
)

from kiro_crew.apps.builtins.dev_fleet import runtime, worktree_ops


@pytest.mark.asyncio
async def test_the_private_common_dir_lives_in_the_owner_only_run_dir_not_the_shared_parent(
    repo, monkeypatch  # noqa: F811
):
    """The shared worktree parent is writable by every agent; ``<data home>/run`` is not.

    A common dir created beside the staging tree could have a ``filter.<name>.smudge``
    planted in its ``config`` by a same-user process before ``read-tree`` read it --
    ``mkdtemp``'s 0700 keeps other users out, not the same uid.
    """
    from kiro_crew.config.paths import data_home

    git = _Git()
    seen: dict[str, str] = {}

    async def capturing(cmd, **kw):
        if "read-tree" in cmd:
            common = Path(kw["env"]["GIT_COMMON_DIR"])
            seen["common"] = str(common)
            seen["root_mode"] = oct(common.parent.stat().st_mode & 0o777)
            seen["mode"] = oct(common.stat().st_mode & 0o777)
        return await git(cmd, **kw)

    monkeypatch.setattr(runtime, "_run_cmd", capturing)
    got = await worktree_ops._release_channel_create()
    assert got["ok"] is True, got
    common = Path(seen["common"])
    staging_parent = Path((git.argv_with("add") or [])[-2]).parent
    assert common.parent == data_home() / "run" / "dev-fleet-gitcommon"
    assert common.parent != staging_parent
    assert common.parent != Path(repo).parent
    if os.name == "posix":
        assert seen["mode"] == "0o700"
        assert seen["root_mode"] == "0o700"


@pytest.mark.skipif(os.name != "posix", reason="ownership and mode are POSIX facts")
def test_an_overly_open_private_root_is_tightened_and_a_link_is_refused(monkeypatch):
    from kiro_crew.config.paths import data_home

    root = data_home() / "run" / "dev-fleet-gitcommon"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o777)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions  # noqa: E501  # fmt: skip
    assert worktree_ops._hermetic_common_root() == str(root)
    assert root.stat().st_mode & 0o777 == 0o700
    root.rmdir()
    elsewhere = data_home() / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    root.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError):
        worktree_ops._hermetic_common_root()
    root.unlink()


@pytest.mark.asyncio
@requires_git
async def test_a_driver_planted_in_the_shared_parent_or_a_hostile_global_config_never_runs(
    tmp_path, monkeypatch
):
    """Real git: a same-user writer racing the populate, plus hostile ambient config.

    Just before ``read-tree`` spawns, a stand-in attacker writes a ``filter.x.smudge``
    driver into the ``config`` of every git common dir it can find in the SHARED
    worktree parent and in the common dir the
    spawn names if that dir is in the shared parent. The operator's global and system
    config (``HOME``, ``XDG_CONFIG_HOME``, ``GIT_CONFIG_GLOBAL``/``SYSTEM``) declare the
    same driver. The committed tree maps the file to it. The marker must not appear.
    """
    home = tmp_path / "home"
    home.mkdir()
    env = _fixture_git_env(home)
    primary = tmp_path / "KiroCrew"  # brand-ok: directory name, not prose
    primary.mkdir()
    marker = tmp_path / "planted-filter-ran"
    driver = f"printf ran > {shlex.quote(marker.as_posix())}; cat"
    hostile = f'[filter "x"]\n\tsmudge = {driver}\n\trequired = true\n'
    (primary / "payload.txt").write_text("release payload\n", encoding="utf-8")
    (primary / ".gitattributes").write_text("payload.txt filter=x\n", encoding="utf-8")
    for argv in (
        ["git", "init", "-q"],
        ["git", "symbolic-ref", "HEAD", "refs/heads/main"],
        ["git", "add", "payload.txt", ".gitattributes"],
        ["git", "commit", "-q", "-m", "one"],
    ):
        rc, _out, err = await _spawn(argv, cwd=str(primary), env=env)
        assert rc == 0, f"fixture setup failed: {argv} -> {err}"
    rc, out, err = await _spawn(["git", "rev-parse", "HEAD"], cwd=str(primary), env=env)
    assert rc == 0, err
    oid = out.strip()

    # Hostile ambient config: every scope git reads by default names the driver.
    hostile_home = tmp_path / "hostile-home"
    (hostile_home / ".config" / "git").mkdir(parents=True)
    (hostile_home / ".gitconfig").write_text(hostile, encoding="utf-8")
    (hostile_home / ".config" / "git" / "config").write_text(hostile, encoding="utf-8")
    hostile_file = tmp_path / "hostile.gitconfig"
    hostile_file.write_text(hostile, encoding="utf-8")
    monkeypatch.setenv("HOME", str(hostile_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile_home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile_file))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(hostile_file))

    staging = tmp_path / "release-channel-stable.staging.planted"
    planted: list[str] = []

    def plant(directory: Path) -> None:
        cfg = directory / "config"
        if cfg.is_file():
            with cfg.open("a", encoding="utf-8") as handle:
                handle.write(hostile)
            planted.append(str(directory))

    async def racing_git(cmd, *, cwd=None, env=None, **kw):
        if "read-tree" in cmd:
            for entry in staging.parent.iterdir():
                if entry.is_dir() and "gitcommon" in entry.name:
                    plant(entry)
            common = Path((env or {})["GIT_COMMON_DIR"])
            if common.parent == staging.parent:
                plant(common)
            # The populate's own env, as given: it was built from the hostile
            # `os.environ` above, which is exactly what must not reach git.
            return await _spawn(list(cmd), cwd=cwd or str(primary), env=dict(env or {}))
        base = dict(_fixture_git_env(home))
        base.update(env or {})
        return await _spawn(list(cmd), cwd=cwd or str(primary), env=base)

    monkeypatch.setattr(runtime, "_run_cmd", racing_git)
    rc, _out, err = await _spawn(
        ["git", "worktree", "add", "--no-checkout", "--detach", str(staging), oid],
        cwd=str(primary),
        env=env,
    )
    assert rc == 0, err

    # Control: the hostile ambient config is armed -- an ordinary read-tree in a
    # second worktree, under the same environment, runs the driver.
    control = tmp_path / "release-channel-stable.staging.control"
    rc, _out, err = await _spawn(
        ["git", "worktree", "add", "--no-checkout", "--detach", str(control), oid],
        cwd=str(primary),
        env=env,
    )
    assert rc == 0, err
    ambient = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "XDG_CONFIG_HOME")}
    ambient.update(GIT_CONFIG_GLOBAL=str(hostile_file), GIT_CONFIG_SYSTEM=str(hostile_file))
    ambient.update(git_maintenance_off_entries(ambient))
    rc, _out, err = await _spawn(
        ["git", "read-tree", "-u", "--reset", oid], cwd=str(control), env=ambient
    )
    assert rc == 0, err
    assert marker.exists(), "the fixture never armed the hostile global config"
    marker.unlink()

    assert await worktree_ops._populate_release_tree(str(primary), str(staging), oid) is None

    assert not marker.exists(), "a planted or ambient smudge driver was executed"
    assert planted == [], f"a common dir was reachable in the shared parent: {planted}"
    assert (staging / "payload.txt").read_text(encoding="utf-8") == "release payload\n"

"""Tests for the EvilKit OS appliance seed generator (pure, stdlib-only)."""

import importlib.util
import json
import subprocess

import pytest

from evilkit.appliance import (
    ApplianceSpec,
    MANIFEST_PATH,
    render_bootstrap,
    render_manifest,
    render_systemd_unit,
    render_user_data,
    write_seed,
)

_HAS_YAML = importlib.util.find_spec("yaml") is not None


def _spec(**overrides) -> ApplianceSpec:
    kwargs = dict(hostname="node1", admin_user="op", scope="10.0.0.0/24")
    kwargs.update(overrides)
    return ApplianceSpec(**kwargs)


def test_defaults_are_valid():
    assert _spec().validate() == []


def test_validate_hostname_whitespace():
    assert _spec(hostname="bad host").validate()


def test_validate_admin_user_whitespace():
    assert _spec(admin_user="bad user").validate()


def test_validate_mesh_leader_scheme():
    assert _spec(mesh_leader="10.0.0.1:8765", mesh_token="t").validate()


def test_validate_mesh_token_requires_leader():
    assert _spec(mesh_token="t").validate()


def test_validate_mesh_leader_requires_token():
    assert _spec(mesh_leader="http://10.0.0.1:8765").validate()


def test_bootstrap_is_valid_bash():
    script = render_bootstrap(_spec())
    assert script.startswith("#!/usr/bin/env bash")
    # `bash -n` parses without executing — the syntax gate for a first-boot script.
    result = subprocess.run(["bash", "-n"], input=script.encode(), capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_bootstrap_records_scope_and_hostname():
    script = render_bootstrap(_spec(scope="10.99.50.0/24", hostname="drop01"))
    assert 'scope = "10.99.50.0/24"' in script
    assert 'hostname = "drop01"' in script


def test_bootstrap_writes_manifest_sentinel():
    script = render_bootstrap(_spec())
    assert MANIFEST_PATH in script


def test_systemd_unit_runs_once():
    unit = render_systemd_unit(_spec())
    assert f"ConditionPathExists=!{MANIFEST_PATH}" in unit
    assert "Type=oneshot" in unit
    assert "ExecStart=/opt/evilkit-os/bootstrap.sh" in unit


def test_manifest_never_carries_token():
    spec = _spec(mesh_leader="http://10.0.0.1:8765", mesh_token="s3cr3t-token")
    manifest = render_manifest(spec)
    assert manifest["mesh_token"] == "present"
    assert "s3cr3t-token" not in json.dumps(manifest)


def test_user_data_injects_ssh_keys_and_scope():
    spec = _spec(ssh_keys=["ssh-ed25519 AAAAtest operator@host"])
    ud = render_user_data(spec)
    assert "ssh-ed25519 AAAAtest operator@host" in ud
    assert "10.0.0.0/24" in ud


def test_token_lands_0600_and_not_in_default_output():
    spec = _spec(mesh_leader="http://10.0.0.1:8765", mesh_token="s3cr3t-token")
    ud = render_user_data(spec)
    assert "s3cr3t-token" in ud  # the token has to reach the box somehow
    assert '"0600"' in ud
    # No token by default.
    assert "mesh-token" not in render_user_data(_spec())


def test_write_seed_writes_every_artifact(tmp_path):
    files = write_seed(_spec(), tmp_path)
    assert set(files) == {
        "user-data",
        "meta-data",
        "bootstrap.sh",
        "evilkit-os.service",
        "manifest.json",
    }
    for name, path in files.items():
        assert path.is_file(), name
        assert path.read_text(encoding="utf-8"), name


def test_write_seed_rejects_invalid_spec(tmp_path):
    with pytest.raises(ValueError):
        write_seed(_spec(hostname="bad host"), tmp_path)


@pytest.mark.skipif(not _HAS_YAML, reason="PyYAML not installed")
def test_user_data_is_valid_yaml():
    import yaml

    spec = _spec(
        ssh_keys=["ssh-ed25519 AAAAtest operator@host"],
        mesh_leader="http://10.0.0.1:8765",
        mesh_token="s3cr3t-token",
    )
    data = yaml.safe_load(render_user_data(spec))
    assert data["hostname"] == "node1"
    assert data["users"][0]["name"] == "op"
    assert data["users"][0]["ssh_authorized_keys"] == ["ssh-ed25519 AAAAtest operator@host"]
    # The multi-line bootstrap content survives as a real multi-line string.
    bootstrap = next(w for w in data["write_files"] if w["path"].endswith("bootstrap.sh"))
    assert bootstrap["content"].startswith("#!/usr/bin/env bash")
    assert "\n" in bootstrap["content"]
    token = next(w for w in data["write_files"] if w["path"].endswith("mesh-token"))
    assert token["permissions"] == "0600"

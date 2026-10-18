"""Tests for the EvilKit OS Pi image build driver (pure renderers + validation)."""

import subprocess

import pytest

from evilkit.build import (
    BuildError,
    PiBuildSpec,
    _load_ssh_keys,
    _mtools_plan,
    build_pi_image,
    render_cmdline,
    render_firstrun,
    render_manifest_md,
    render_userconf,
)


def _spec(tmp_path, **overrides) -> PiBuildSpec:
    wheel = tmp_path / "evilkit_os-2.0.0-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04" + b"x" * 128)
    base = tmp_path / "base.img"
    base.write_bytes(b"\x00" * 1024)
    kwargs = dict(
        hostname="drop01",
        wheel=wheel,
        base_image=base,
        output=tmp_path / "drop.img",
        ssh_keys=["ssh-ed25519 AAAAtest operator@host"],
    )
    kwargs.update(overrides)
    return PiBuildSpec(**kwargs)


def _full(tmp_path, **overrides) -> PiBuildSpec:
    return _spec(
        tmp_path,
        scope="10.99.50.0/24,10.50.0.0/24",
        mesh_leader="http://100.88.148.72:8765",
        mesh_token="s3cr3t-mesh-token",
        eth0_ip="10.99.50.60/24",
        gateway="10.99.50.1",
        wifi_ssid="lab-net",
        wifi_psk="labnet12345",
        **overrides,
    )


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def test_spec_defaults_valid(tmp_path):
    assert _spec(tmp_path).validate() == []


def test_spec_requires_ssh_key(tmp_path):
    assert _spec(tmp_path, ssh_keys=[]).validate()


def test_spec_requires_existing_wheel(tmp_path):
    assert _spec(tmp_path, wheel=tmp_path / "missing.whl").validate()


def test_spec_requires_existing_base(tmp_path):
    assert _spec(tmp_path, base_image=tmp_path / "missing.img").validate()


def test_spec_output_must_differ_from_base(tmp_path):
    base = tmp_path / "base.img"
    base.write_bytes(b"\x00" * 16)
    assert _spec(tmp_path, base_image=base, output=base).validate()


def test_spec_eth0_gateway_pairing(tmp_path):
    assert _spec(tmp_path, eth0_ip="10.99.50.60/24").validate()
    assert _spec(tmp_path, gateway="10.99.50.1").validate()


def test_spec_eth0_must_be_cidr(tmp_path):
    assert _spec(tmp_path, eth0_ip="10.99.50.60", gateway="10.99.50.1").validate()


def test_spec_wifi_pairing(tmp_path):
    assert _spec(tmp_path, wifi_ssid="lab-net").validate()
    assert _spec(tmp_path, wifi_psk="labnet12345").validate()


def test_spec_mesh_pairing(tmp_path):
    assert _spec(tmp_path, mesh_leader="http://10.0.0.1:8765").validate()
    assert _spec(tmp_path, mesh_token="tok").validate()


def test_spec_mesh_leader_scheme(tmp_path):
    assert _spec(tmp_path, mesh_leader="10.0.0.1:8765", mesh_token="tok").validate()


# ---------------------------------------------------------------------------
# render_firstrun
# ---------------------------------------------------------------------------

def test_firstrun_is_valid_bash(tmp_path):
    script = render_firstrun(_full(tmp_path))
    assert script.startswith("#!/bin/bash")
    result = subprocess.run(["bash", "-n"], input=script.encode(), capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_firstrun_records_scope_hostname_wheel(tmp_path):
    script = render_firstrun(_full(tmp_path))
    assert "HOSTNAME_NEW=drop01" in script
    assert 'EVILKIT_SCOPE=10.99.50.0/24,10.50.0.0/24' in script
    assert "WHEEL=/boot/firmware/evilkit/evilkit_os-2.0.0-py3-none-any.whl" in script


def test_firstrun_eth0_wifi_mesh_present_when_requested(tmp_path):
    script = render_firstrun(_full(tmp_path))
    assert "addresses=10.99.50.60/24" in script
    assert "gateway=10.99.50.1" in script
    assert "dns=1.1.1.1;9.9.9.9;" in script
    assert "ssid=lab-net" in script
    assert "psk=labnet12345" in script
    assert "evilk-mesh-worker-pi.service" in script


def test_firstrun_omits_optional_sections_when_absent(tmp_path):
    script = render_firstrun(_spec(tmp_path))
    assert "eth0-static.nmconnection" not in script
    assert "evilkit-wifi.nmconnection" not in script
    assert "evilk-mesh-worker-pi.service" not in script
    assert 'mesh_leader = ' not in script
    # still a valid script
    result = subprocess.run(["bash", "-n"], input=script.encode(), capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_firstrun_locks_admin_password(tmp_path):
    script = render_firstrun(_spec(tmp_path, admin_user="operator"))
    assert "id -u operator" in script
    assert "passwd -l operator" in script
    assert "/home/operator/.ssh" in script


def test_firstrun_has_no_unsubstituted_tokens(tmp_path):
    script = render_firstrun(_full(tmp_path))
    assert "@" not in script.replace("$MESH_LEADER", "").replace("$(date", "").replace("@\"", "")


# ---------------------------------------------------------------------------
# render_cmdline / render_userconf
# ---------------------------------------------------------------------------

def test_render_cmdline_appends_hook():
    base = (
        "console=serial0,115200 root=PARTUUID=8a438930-02 rootfstype=ext4 "
        "rootwait init=/usr/lib/raspberrypi-sys-mods/firstboot"
    )
    out = render_cmdline(base)
    assert "root=PARTUUID=8a438930-02" in out
    assert "systemd.run=/boot/firmware/firstrun.sh" in out
    assert "systemd.run_success_action=reboot" in out


def test_render_cmdline_rewrites_stale_hook():
    base = (
        "root=PARTUUID=8a438930-02 rootfstype=ext4 "
        "systemd.run=/old/firstrun.sh systemd.unit=old.target"
    )
    out = render_cmdline(base)
    assert "systemd.run=/old/firstrun.sh" not in out
    assert "systemd.unit=old.target" not in out
    assert "systemd.run=/boot/firmware/firstrun.sh" in out


def test_render_userconf_format(tmp_path):
    assert render_userconf(_spec(tmp_path), "$6$salt$hash") == "pi:$6$salt$hash\n"


# ---------------------------------------------------------------------------
# manifest / plan
# ---------------------------------------------------------------------------

def test_manifest_redacts_token_and_psk(tmp_path):
    spec = _full(tmp_path)
    plan = _mtools_plan(tmp_path, f"{spec.output}@@4194304", spec.wheel.name, True)
    md = render_manifest_md(spec, "deadbeef", "root=x", plan, "$6$salt$hash")
    assert "s3cr3t-mesh-token" not in md
    assert "labnet12345" not in md
    assert "present" in md          # mesh token shown as present (redacted)
    assert "PSK redacted" in md
    assert "deadbeef" in md


def test_plan_shape(tmp_path):
    spec = _full(tmp_path)
    plan = _mtools_plan(tmp_path, "drop.img@@4194304", spec.wheel.name, True)
    assert len(plan) == 5
    assert plan[0][0] == "mcopy" and plan[0][-1] == "::/"
    assert plan[1] == ["mmd", "-i", "drop.img@@4194304", "::/evilkit"]
    assert plan[2][-1] == "::/evilkit/"
    assert plan[3] == ["mdel", "-i", "drop.img@@4194304", "::/cmdline.txt"]
    assert plan[4][-1] == "::/"


def test_plan_omits_token_when_absent(tmp_path):
    plan = _mtools_plan(tmp_path, "drop.img@@4194304", "evilkit.whl", False)
    evilkit_cmd = plan[2]
    assert "mesh-token" not in " ".join(evilkit_cmd)
    assert "evilkit.whl" in " ".join(evilkit_cmd)


def test_load_ssh_keys_literal_and_file(tmp_path):
    pub = tmp_path / "id.pub"
    pub.write_text("ssh-ed25519 AAAAfiledata file@host\n")
    lines = _load_ssh_keys(["ssh-ed25519 AAAAliteral lit@host", str(pub)])
    assert lines == ["ssh-ed25519 AAAAliteral lit@host", "ssh-ed25519 AAAAfiledata file@host"]


def test_build_rejects_invalid_spec(tmp_path):
    with pytest.raises(BuildError):
        build_pi_image(_spec(tmp_path, ssh_keys=[]))


def test_build_dry_run_renders_without_writing_image(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "evilkit.build._read_cmdline",
        lambda image, boot_offset: "root=PARTUUID=8a438930-02 rootfstype=ext4 rootwait",
    )
    spec = _spec(tmp_path, userconf_hash="$6$salt$hash")
    result = build_pi_image(spec, dry_run=True)
    assert result.dry_run is True
    assert result.output is None
    assert len(result.plan) == 5
    assert not spec.output.exists()
    bake_dir = spec.output.parent / (spec.output.name + ".bake")
    assert (bake_dir / "firstrun.sh").is_file()
    assert (bake_dir / "cmdline.txt").is_file()
    assert (bake_dir / "authorized_keys").is_file()

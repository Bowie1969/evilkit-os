"""EvilKit OS — the image build driver.

``evilkit appliance build`` closes the loop from the appliance seed to a flashed
drop. It renders the first-boot artifacts (``firstrun.sh``, ``cmdline.txt``,
``userconf.txt``, the SSH marker, ``authorized_keys``, the mesh token and the
baked wheel) and writes them into the boot partition of a Raspberry Pi OS image —
**root-free, using mtools only**, exactly the procedure the hand-built
``evilkit-os-pi.img`` used. The ext4 rootfs is never mounted.

The renderers are pure text and trivially testable; the build step only shells
out to ``mtools``/``xz``/``openssl``, which are build-time tools. The packaged
``evilkit`` CLI itself stays stdlib-only.

Safety properties, inherited from the hand build:

- No secret is written to ``manifest.md`` — the mesh token and the Wi-Fi PSK are
  redacted (``present`` / ``redacted``).
- The rendered ``firstrun.sh`` is ``bash -n`` clean and re-read back from the
  image for verification; the baked wheel's sha256 is re-read and compared.
- ``build_pi_image`` validates the spec before touching a disk image and refuses
  an output path that equals the base image.
"""

from __future__ import annotations

import hashlib
import lzma
import secrets
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "BuildError",
    "BuildResult",
    "PiBuildSpec",
    "render_firstrun",
    "render_cmdline",
    "render_userconf",
    "render_manifest_md",
    "build_pi_image",
    "verify_image",
]

# Raspberry Pi OS "bookworm" images place the FAT32 boot partition at this byte
# offset; mtools addresses a raw file with the ``file@@offset`` syntax.
DEFAULT_BOOT_OFFSET = 4194304


class BuildError(RuntimeError):
    """Raised when a build cannot proceed or fails verification."""


@dataclass
class PiBuildSpec:
    """Everything needed to bake an EvilKit OS Pi drop image."""

    hostname: str
    wheel: Path
    base_image: Path
    output: Path
    ssh_keys: list[str] = field(default_factory=list)
    admin_user: str = "pi"
    scope: str = "solo"
    mesh_leader: str | None = None
    mesh_token: str | None = None
    eth0_ip: str | None = None
    gateway: str | None = None
    dns: str = "1.1.1.1 9.9.9.9"
    wifi_ssid: str | None = None
    wifi_psk: str | None = None
    wifi_country: str = "AU"
    boot_offset: int = DEFAULT_BOOT_OFFSET
    # A pre-computed crypt(3) hash for userconf.txt; generated at build time when
    # omitted (openssl passwd -6). Never stored in the manifest.
    userconf_hash: str | None = None

    def validate(self) -> list[str]:
        """Return a list of human-readable problems; empty means valid."""
        problems: list[str] = []
        if not self.hostname or any(ch.isspace() for ch in self.hostname):
            problems.append("hostname must be a single non-empty token")
        if not self.admin_user or any(ch.isspace() for ch in self.admin_user):
            problems.append("admin_user must be a single non-empty token")
        if not self.ssh_keys:
            problems.append("at least one --ssh-key is required")
        if not self.wheel.is_file():
            problems.append(f"wheel not found: {self.wheel}")
        if not self.base_image.is_file():
            problems.append(f"base image not found: {self.base_image}")
        if self.output.resolve() == self.base_image.resolve():
            problems.append("output must differ from the base image")
        if (self.eth0_ip is None) != (self.gateway is None):
            problems.append("eth0_ip and gateway must be given together")
        if self.eth0_ip is not None and "/" not in self.eth0_ip:
            problems.append("eth0_ip must be CIDR notation, e.g. 10.99.50.60/24")
        if (self.wifi_ssid is None) != (self.wifi_psk is None):
            problems.append("wifi_ssid and wifi_psk must be given together")
        if (self.mesh_leader is None) != (self.mesh_token is None):
            problems.append("mesh_leader and mesh_token must be given together")
        if self.mesh_leader is not None and not self.mesh_leader.startswith(("http://", "https://")):
            problems.append("mesh_leader must be an http(s) URL")
        return problems


@dataclass
class BuildResult:
    """What ``build_pi_image`` produced. ``output`` is None on a dry run."""

    output: Path | None
    manifest: str
    plan: list[list[str]]
    dry_run: bool


# ---------------------------------------------------------------------------
# Pure renderers
# ---------------------------------------------------------------------------

_FIRSTRUN = r'''#!/bin/bash
# firstrun.sh — EvilKit OS first boot (Raspberry Pi OS bookworm lite).
# Invoked by systemd.run=/boot/firmware/firstrun.sh from cmdline.txt; runs as
# root during early boot. Everything critical is baked into
# /boot/firmware/evilkit/, so first boot works fully offline (the drop Pi sits
# on the air-gapped range). Logs to /boot/firmware/firstrun.log for post-mortem
# inspection via a card reader on another box.
set +e
exec > >(tee /boot/firmware/firstrun.log) 2>&1
echo "=== evilkit-os firstrun start: $(date -u +%FT%TZ) ==="

HOSTNAME_NEW=@HOSTNAME@
MESH_LEADER=@MESH_LEADER@
EVILKIT_SCOPE=@SCOPE@
WHEEL=/boot/firmware/evilkit/@WHEEL@

# ---------- 1. hostname ----------
echo "$HOSTNAME_NEW" > /etc/hostname
if grep -q '^127\.0\.1\.1' /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME_NEW/" /etc/hosts
else
    echo -e "127.0.1.1\t$HOSTNAME_NEW" >> /etc/hosts
fi
hostnamectl set-hostname "$HOSTNAME_NEW" || true

# ---------- 2. SSH key for user @ADMIN_USER@ (created by userconf.txt earlier in boot) ----------
if ! id -u @ADMIN_USER@ >/dev/null 2>&1; then
    echo "WARN: @ADMIN_USER@ user missing — recreating"
    useradd -m -s /bin/bash -G sudo,dialout,audio,video,plugdev,games,users,input,netdev,gpio @ADMIN_USER@
fi
install -d -m 0700 -o @ADMIN_USER@ -g @ADMIN_USER@ /home/@ADMIN_USER@/.ssh
install -m 0600 -o @ADMIN_USER@ -g @ADMIN_USER@ /boot/firmware/evilkit/authorized_keys /home/@ADMIN_USER@/.ssh/authorized_keys
# Lock the @ADMIN_USER@ password — key-only
passwd -l @ADMIN_USER@ || true

# ---------- 3. SSH hardening ----------
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
systemctl enable ssh 2>/dev/null || true

@ETH0_BLOCK@
@WIFI_BLOCK@
# ---------- 6. Wi-Fi regulatory country ----------
if command -v raspi-config >/dev/null 2>&1; then
    raspi-config nonint do_wifi_country @WIFI_COUNTRY@ || true
fi
if [ -f /etc/default/crda ]; then
    sed -i 's/^REGDOMAIN=.*/REGDOMAIN=@WIFI_COUNTRY@/' /etc/default/crda || true
fi

# ---------- 7. wait for network (bounded, non-fatal) ----------
echo "Waiting for network..."
for i in $(seq 1 30); do
    if getent hosts deb.debian.org >/dev/null 2>&1; then
        echo "network up after ${i}0s"
        break
    fi
    sleep 10
done

# ---------- 8. apt extras (best effort; the drop Pi is usually air-gapped) ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update || true
apt-get install -y --no-install-recommends tcpdump tmux nmap python3 curl ca-certificates || true

# ---------- 9. Tailscale — only when a fresh authkey was baked in ----------
# Tailscale authkeys are one-time: a used key cannot be re-baked. When no
# tskey is present the node stays reachable via static eth0 and the lab-net
# Wi-Fi; mint a key and re-add it later via `tailscale up` over SSH.
if [ -f /boot/firmware/evilkit/ts-authkey ]; then
    if ! command -v tailscale >/dev/null 2>&1; then
        curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bookworm.noarmor.gpg \
            | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
        curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bookworm.tailscale-keyring.list \
            | tee /etc/apt/sources.list.d/tailscale.list >/dev/null
        apt-get update
        apt-get install -y tailscale
    fi
    systemctl enable --now tailscaled
    sleep 3
    tailscale up --authkey="$(cat /boot/firmware/evilkit/ts-authkey)" \
        --hostname="$HOSTNAME_NEW" --ssh --accept-dns=false || true
    tailscale status || true
else
    echo "tailscale skipped: no ts-authkey baked"
fi

# ---------- 10. EvilKit OS — offline install from the baked wheel ----------
# The wheel is stdlib-only, so it installs without pip or a network: extract it
# and run the package with a PYTHONPATH shim. No venv, no index, no egress.
install -d -m 0755 /opt/evilkit-os
python3 -c "import zipfile; zipfile.ZipFile('$WHEEL').extractall('/opt/evilkit-os/site')"
cat > /usr/local/bin/evilkit <<'EOF'
#!/bin/sh
PYTHONPATH=/opt/evilkit-os/site exec /usr/bin/python3 -m evilkit "$@"
EOF
chmod 0755 /usr/local/bin/evilkit
install -d -m 0755 /etc/evilkit-os
cat > /etc/evilkit-os/config.toml <<EOF
# EvilKit OS appliance config (generated at first boot)
hostname = "$HOSTNAME_NEW"
scope = "$EVILKIT_SCOPE"
@MESH_LEADER_LINE@
EOF
cat > /opt/evilkit-os/manifest.json <<EOF
{"hostname": "$HOSTNAME_NEW", "scope": "$EVILKIT_SCOPE", "bootstrapped_at": "$(date -Is)"}
EOF
echo "--- evilkit smoke test ---"
/usr/local/bin/evilkit --version || echo "WARN: evilkit import failed on first boot"

@MESH_WORKER_BLOCK@
# ---------- 12. tcpdump rotating capture on eth0 (local only, pull via rsync post-flash) ----------
install -d -m 0755 /var/log/pcaps
cat > /etc/systemd/system/tcpdump-eth0.service <<'EOF'
[Unit]
Description=Rotating eth0 pcap capture (drop-node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/tcpdump -i eth0 -w /var/log/pcaps/eth0-%%Y%%m%%d-%%H.pcap -G 3600 -W 48 -z gzip -K -n
Restart=on-failure
RestartSec=10
# contain it
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log/pcaps

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tcpdump-eth0.service

# ---------- 13. remove firstrun from cmdline, delete payload ----------
sed -i 's| systemd.run=[^ ]*||g; s| systemd.run_success_action=[^ ]*||g; s| systemd.unit=[^ ]*||g' /boot/firmware/cmdline.txt

# Preserve firstrun.log on the boot partition for first-boot diagnosis, delete the rest
rm -f /boot/firmware/firstrun.sh
rm -rf /boot/firmware/evilkit

sync
echo "=== evilkit-os firstrun complete: $(date -u +%FT%TZ) ==="
echo "Rebooting..."
sleep 2
reboot
'''

_ETH0_BLOCK = r'''# ---------- 4. NetworkManager static eth0 ----------
install -d -m 0700 /etc/NetworkManager/system-connections
cat > /etc/NetworkManager/system-connections/eth0-static.nmconnection <<'EOF'
[connection]
id=eth0-static
type=ethernet
interface-name=eth0
autoconnect=true
autoconnect-priority=20

[ipv4]
method=manual
addresses=@ETH0_IP@
gateway=@GATEWAY@
dns=@DNS@;

[ipv6]
method=disabled
EOF
chmod 600 /etc/NetworkManager/system-connections/eth0-static.nmconnection
'''

_WIFI_BLOCK = r'''# ---------- 5. NetworkManager Wi-Fi ----------
cat > /etc/NetworkManager/system-connections/evilkit-wifi.nmconnection <<'EOF'
[connection]
id=@WIFI_SSID@
type=wifi
autoconnect=true
autoconnect-priority=10

[wifi]
mode=infrastructure
ssid=@WIFI_SSID@

[wifi-security]
key-mgmt=wpa-psk
psk=@WIFI_PSK@

[ipv4]
method=auto

[ipv6]
method=disabled
EOF
chmod 600 /etc/NetworkManager/system-connections/evilkit-wifi.nmconnection
'''

_MESH_WORKER_BLOCK = r'''# ---------- 11. mesh worker (evilk user + unit running `evilkit mesh work`) ----------
if ! id -u evilk >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/evilk-mesh --create-home --shell /usr/sbin/nologin evilk
fi
install -d -m 0700 -o root -g root /etc/evilk-mesh
install -m 0640 -o root -g evilk /boot/firmware/evilkit/mesh-token /etc/evilk-mesh/token

cat > /etc/evilk-mesh/worker.env <<EOF
EVILK_MESH_LEADER=$MESH_LEADER
EVILK_MESH_TOKEN_FILE=/etc/evilk-mesh/token
EVILK_MESH_NAME=$HOSTNAME_NEW
EOF
chmod 0640 /etc/evilk-mesh/worker.env
chown root:evilk /etc/evilk-mesh/worker.env

cat > /etc/systemd/system/evilk-mesh-worker-pi.service <<'EOF'
[Unit]
Description=EvilKit OS mesh worker (pulls tasks from the Parrot hub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=evilk
WorkingDirectory=/var/lib/evilk-mesh
EnvironmentFile=/etc/evilk-mesh/worker.env
ExecStart=/usr/local/bin/evilkit mesh work \
    --leader ${EVILK_MESH_LEADER} \
    --token-file ${EVILK_MESH_TOKEN_FILE} \
    --name ${EVILK_MESH_NAME} \
    --wait
Restart=always
RestartSec=5

# The Pi has no persistent storage worth trusting; keep the worker contained.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/evilk-mesh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable evilk-mesh-worker-pi.service
'''


def _sub(template: str, **mapping: str) -> str:
    for token, value in mapping.items():
        template = template.replace("@" + token + "@", value)
    return template


def render_firstrun(spec: PiBuildSpec) -> str:
    """Render the first-boot script for the Pi (substitutes validated fields)."""
    dns_nm = ";".join(spec.dns.split())
    # The conditional blocks carry their own @TOKEN@ placeholders, so render them
    # first; the main pass only substitutes the block markers and shared scalars.
    eth0_block = (
        _sub(_ETH0_BLOCK, ETH0_IP=spec.eth0_ip or "", GATEWAY=spec.gateway or "", DNS=dns_nm)
        if spec.eth0_ip
        else ""
    )
    wifi_block = (
        _sub(_WIFI_BLOCK, WIFI_SSID=spec.wifi_ssid or "", WIFI_PSK=spec.wifi_psk or "")
        if spec.wifi_ssid
        else ""
    )
    mesh_block = _MESH_WORKER_BLOCK if spec.mesh_leader else ""
    return _sub(
        _FIRSTRUN,
        HOSTNAME=spec.hostname,
        ADMIN_USER=spec.admin_user,
        MESH_LEADER=spec.mesh_leader or "",
        MESH_LEADER_LINE='mesh_leader = "$MESH_LEADER"' if spec.mesh_leader else "",
        SCOPE=spec.scope,
        WHEEL=spec.wheel.name,
        WIFI_COUNTRY=spec.wifi_country,
        ETH0_BLOCK=eth0_block,
        WIFI_BLOCK=wifi_block,
        MESH_WORKER_BLOCK=mesh_block,
    )


def render_cmdline(base_cmdline: str) -> str:
    """Append the firstrun hook to a base ``cmdline.txt``, dropping any stale hook.

    The base image's own ``root=PARTUUID=...`` is preserved — only the
    ``systemd.run*`` / ``systemd.unit`` tokens are rewritten.
    """
    tokens = [
        t
        for t in base_cmdline.split()
        if not t.startswith(("systemd.run=", "systemd.run_success_action=", "systemd.unit="))
    ]
    tokens += [
        "systemd.run=/boot/firmware/firstrun.sh",
        "systemd.run_success_action=reboot",
        "systemd.unit=kernel-command-line.target",
    ]
    return " ".join(tokens)


def render_userconf(spec: PiBuildSpec, password_hash: str) -> str:
    return f"{spec.admin_user}:{password_hash}\n"


def render_manifest_md(
    spec: PiBuildSpec,
    wheel_sha: str,
    base_cmdline: str,
    plan: list[list[str]],
    password_hash: str,
) -> str:
    """A build-time markdown manifest. Never carries the mesh token or Wi-Fi PSK."""
    lines = [
        "# evilkit-os — image manifest (generated by `evilkit appliance build`)",
        "",
        f"Built: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Base image: `{spec.base_image}`",
        f"Output: `{spec.output}`",
        f"Boot partition offset: {spec.boot_offset}",
        "",
        "## Baked-in config",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Hostname | `{spec.hostname}` |",
        f"| Admin user | `{spec.admin_user}` (password locked at first boot, key-only) |",
        f"| SSH keys | {len(spec.ssh_keys)} |",
        f"| Scope | `{spec.scope}` |",
        f"| Mesh leader | `{spec.mesh_leader or 'none'}` |",
        f"| Mesh token | {'`present` (redacted)' if spec.mesh_token else 'none'} |",
        f"| eth0 | {spec.eth0_ip + ' gw ' + spec.gateway if spec.eth0_ip else 'DHCP'} |",
        f"| Wi-Fi | {spec.wifi_ssid + ' (PSK redacted)' if spec.wifi_ssid else 'none'} |",
        f"| Wi-Fi country | `{spec.wifi_country}` |",
        f"| Wheel | `{spec.wheel.name}` sha256 `{wheel_sha}` |",
        f"| userconf hash | `{password_hash[:4]}…` (redacted) |",
        "",
        "## cmdline.txt",
        "",
        "```",
        render_cmdline(base_cmdline),
        "```",
        "",
        "## Build method (root-free, mtools)",
        "",
        "```sh",
    ]
    for cmd in plan:
        lines.append(" ".join(shlex.quote(a) for a in cmd))
    lines += ["```", ""]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Build driver
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_ssh_keys(keys: list[str]) -> list[str]:
    """Accept each entry as a literal public key or a path to a key file."""
    lines: list[str] = []
    for key in keys:
        path = Path(key)
        if path.is_file():
            lines += [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        else:
            lines += [ln for ln in key.splitlines() if ln.strip()]
    return lines


def _generate_password_hash() -> str:
    """Generate a throwaway shadow hash with `openssl passwd -6`.

    The password is random and immediately locked by firstrun.sh, so it never
    matters — it only has to be a valid crypt hash for Raspberry Pi OS's
    userconf.txt firstboot.
    """
    password = secrets.token_urlsafe(18)
    result = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=password.encode(),
        capture_output=True,
        check=True,
    )
    return result.stdout.decode().strip()


def _resolve_base(base: Path, tmp: Path) -> Path:
    """Return a raw (uncompressed) base image path, decompressing .xz on the fly."""
    if base.suffix == ".xz":
        raw = tmp / base.name[: -len(".xz")]
        with lzma.open(base, "rb") as src, open(raw, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
        return raw
    return base


def _read_cmdline(image: Path, boot_offset: int) -> str:
    try:
        result = subprocess.run(
            ["mtype", "-i", f"{image}@@{boot_offset}", "::/cmdline.txt"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise BuildError(
            f"cannot read cmdline.txt from base image {image}: {exc.stderr.strip()}"
        ) from exc
    return result.stdout.strip()


def _mtools_plan(
    staging: Path, img_spec: str, wheel_name: str, has_token: bool
) -> list[list[str]]:
    plan: list[list[str]] = []
    plan.append(
        ["mcopy", "-o", "-i", img_spec,
         str(staging / "firstrun.sh"), str(staging / "userconf.txt"), str(staging / "ssh"),
         "::/"]
    )
    plan.append(["mmd", "-i", img_spec, "::/evilkit"])
    evilkit_files = [str(staging / "authorized_keys")]
    if has_token:
        evilkit_files.append(str(staging / "mesh-token"))
    evilkit_files.append(str(staging / wheel_name))
    plan.append(["mcopy", "-o", "-i", img_spec, *evilkit_files, "::/evilkit/"])
    plan.append(["mdel", "-i", img_spec, "::/cmdline.txt"])
    plan.append(["mcopy", "-i", img_spec, str(staging / "cmdline.txt"), "::/"])
    return plan


def verify_image(output: Path, boot_offset: int, wheel_path: Path) -> list[str]:
    """Re-read the baked artifacts and report problems (empty means verified)."""
    problems: list[str] = []
    img_spec = f"{output}@@{boot_offset}"

    firstrun = subprocess.run(
        ["mtype", "-i", img_spec, "::/firstrun.sh"], capture_output=True, text=True
    )
    if firstrun.returncode != 0:
        problems.append(f"cannot read firstrun.sh from image: {firstrun.stderr.strip()}")
    else:
        parsed = subprocess.run(["bash", "-n"], input=firstrun.stdout.encode(), capture_output=True)
        if parsed.returncode != 0:
            problems.append(f"firstrun.sh fails bash -n: {parsed.stderr.decode().strip()}")

    expected = _sha256(wheel_path)
    with tempfile.TemporaryDirectory(prefix="evilkit-verify-") as td:
        wheel_out = Path(td) / wheel_path.name
        copied = subprocess.run(
            ["mcopy", "-o", "-i", img_spec, f"::/evilkit/{wheel_path.name}", str(wheel_out)],
            capture_output=True,
            text=True,
        )
        if copied.returncode != 0:
            problems.append(f"cannot read wheel from image: {copied.stderr.strip()}")
        elif _sha256(wheel_out) != expected:
            problems.append("wheel sha256 mismatch in image")

    return problems


def build_pi_image(spec: PiBuildSpec, *, dry_run: bool = False) -> BuildResult:
    """Render and (unless dry_run) bake an EvilKit OS Pi drop image.

    Returns a :class:`BuildResult`. On failure raises :class:`BuildError` with a
    joined, human-readable reason.
    """
    problems = spec.validate()
    if problems:
        raise BuildError("; ".join(problems))

    ssh_lines = _load_ssh_keys(spec.ssh_keys)
    if not ssh_lines:
        raise BuildError("no usable SSH public key (empty or unreadable)")

    password_hash = spec.userconf_hash or _generate_password_hash()
    wheel_sha = _sha256(spec.wheel)
    bake_dir = spec.output.parent / (spec.output.name + ".bake")
    bake_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="evilkit-os-base-") as td:
        raw_base = _resolve_base(spec.base_image, Path(td))
        base_cmdline = _read_cmdline(raw_base, spec.boot_offset)

    # Render the bake artifacts into a persistent, auditable sibling directory
    # (the "bake dir"), mirroring the hand-build's bake/ layout.
    (bake_dir / "firstrun.sh").write_text(render_firstrun(spec), encoding="utf-8")
    (bake_dir / "ssh").write_text("", encoding="utf-8")
    (bake_dir / "authorized_keys").write_text("\n".join(ssh_lines) + "\n", encoding="utf-8")
    if spec.mesh_token is not None:
        (bake_dir / "mesh-token").write_text(spec.mesh_token, encoding="utf-8")
    shutil.copyfile(spec.wheel, bake_dir / spec.wheel.name)
    (bake_dir / "userconf.txt").write_text(render_userconf(spec, password_hash), encoding="utf-8")
    (bake_dir / "cmdline.txt").write_text(render_cmdline(base_cmdline) + "\n", encoding="utf-8")

    img_spec = f"{spec.output}@@{spec.boot_offset}"
    plan = _mtools_plan(bake_dir, img_spec, spec.wheel.name, spec.mesh_token is not None)
    manifest = render_manifest_md(spec, wheel_sha, base_cmdline, plan, password_hash)

    if dry_run:
        (bake_dir / "PLAN.txt").write_text(
            "\n".join(" ".join(shlex.quote(a) for a in cmd) for cmd in plan) + "\n",
            encoding="utf-8",
        )
        return BuildResult(output=None, manifest=manifest, plan=plan, dry_run=True)

    with tempfile.TemporaryDirectory(prefix="evilkit-os-base-") as td:
        raw_base = _resolve_base(spec.base_image, Path(td))
        shutil.copyfile(raw_base, spec.output)

    for cmd in plan:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            raise BuildError(f"mtools step failed: {' '.join(cmd)}: {exc}") from exc

    errs = verify_image(spec.output, spec.boot_offset, spec.wheel)
    if errs:
        raise BuildError("verification failed: " + "; ".join(errs))

    (spec.output.parent / (spec.output.name + ".manifest.md")).write_text(
        manifest, encoding="utf-8"
    )
    return BuildResult(output=spec.output, manifest=manifest, plan=plan, dry_run=False)

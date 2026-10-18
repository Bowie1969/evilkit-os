# EvilKit OS

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-8A2BE2)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib--only-brightgreen)
![License](https://img.shields.io/badge/license-source--available-lightgrey)

**One CLI that turns the EvilKit operator loop into a bootable, evidence-first
drop node — scope-gated at launch, circuit-breaked at runtime, and scored from
what actually happened.**

## What it is

EvilKit OS is the consolidated, installable **operator system** for authorized
AI security testing. It wraps the operator loop (Kimi Code CLI, Qwen, and the
heretic/GLM local models), the harness and its circuit breakers, the mission
contract, and a hash-chained evidence journal into one package — then bakes the
whole thing into a bootable Raspberry Pi / cloud-init drop image with
`evilkit appliance seed` and `evilkit appliance build`.

### Highlights

- **Fail-closed scope gate** — an authorized target set is resolved, normalised
  and recorded into the engagement `.mcp.json` *before* any agent launches; an
  unrecordable scope is fatal unless `--allow-unscoped`.
- **Circuit-breaked harness** — the L3 per-(host, credential) attempt cap, phase
  gate, loop detection, and a tamper-evident evidence journal bound the run.
- **Evidence-first scoring** — a dashboard telemetry emitter writes the scorer's
  vocabulary (`recon`/`foothold`/`pivot`/`implant`/`persist`/`c2`/`exfil`) so a
  run is scored from events, not a narrative.
- **Bootable appliance** — `seed` renders a cloud-init NoCloud seed; `build`
  writes a Raspberry Pi drop image root-free with mtools only. First boot runs
  exactly once, guarded by a `manifest.json` sentinel.
- **Zero runtime dependencies** — Python 3.11+ standard library only.

## Relationship to the control plane

This repository is the **appliance / operator-system layer** on top of the
[`Bowie1969/evilkit`](https://github.com/Bowie1969/evilkit) control-plane CLI.
The core `evilkit` package here is ported unchanged and tested; what is new in
this repo is the appliance layer (`seed`/`build`), the consolidation, and the
first fixes below.

| Repo | Role |
| --- | --- |
| [`Bowie1969/evilkit`](https://github.com/Bowie1969/evilkit) | Control-plane CLI: scope, operator loop, harness, evidence journal |
| **`Bowie1969/evilkit-os`** (this repo) | Bootable operator-system release: installable package + appliance seed/build |

## The four jobs

One CLI (`evilkit`) does four jobs:

- **Scope gate** — resolve, normalise and record an authorized target set into
  the engagement `.mcp.json` before any agent is launched. Fail-closed: an
  unrecordable scope is fatal unless `--allow-unscoped`.
- **Operator loop** — launch the Kimi Code CLI (or Qwen, or a local heretic/GLM
  model) under the recorded scope, supervised and checkpointed.
- **Harness** — circuit breakers, the L3 per-(host, credential) attempt cap, the
  phase gate, loop detection, and a hash-chained evidence journal.
- **Evidence** — a dashboard telemetry emitter that writes the scorer's
  vocabulary (`recon`/`foothold`/`pivot`/`implant`/`persist`/`c2`/`exfil`) so a
  run is scored from what actually happened, not from a narrative.

## Install

Python 3.11+. Runtime dependencies: none (stdlib only).

```sh
uv tool install --editable .
# or
pip install -e .
```

## Quickstart

```sh
evilkit --scope 10.99.50.0/24          # record the scope, then launch Kimi
evilkit scope show                     # print the recorded scope
evilkit doctor                         # check the wiring
evilkit lessons show                   # operator lessons injected into the prompt
```

## Architecture

```
                  evilkit appliance seed          evilkit appliance build
  evilkit CLI ─────────────────────►  NoCloud  ──────────────────────► Pi / cloud-init
 (control plane)  user-data + meta-data  seed     boot-partition drop      drop image
                  bootstrap.sh + systemd unit     (firstrun.sh, cmdline.txt,
                                                  userconf.txt, wheel, token)

  ┌──────────────────────────── first boot (at most once) ───────────────────────────┐
  │  bootstrap.sh  →  installs /opt/evilkit-os/venv, writes scope + mesh leader       │
  │  systemd unit  →  ConditionPathExists=!manifest  (a failed boot retries)          │
  │  manifest.json →  once-only sentinel written on success                          │
  └────────────────────────────────► enrolled drop node ──────────────────────────────┘
```

## The appliance

`evilkit appliance seed` turns the operator system into a bootable drop node. It
renders a cloud-init **NoCloud** seed (`user-data` + `meta-data`), the first-boot
`bootstrap.sh`, and the systemd unit that runs it — pure text, no image is ever
built or flashed by the tool.

```sh
evilkit appliance seed \
  --hostname drop01 --user operator \
  --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
  --scope 10.99.50.0/24 \
  --mesh-leader http://100.88.148.72:8765 --mesh-token '...' \
  --out-dir ./cidata
```

What first boot does:

1. provisions the `operator` user (key auth only, root disabled);
2. installs the operator system into `/opt/evilkit-os/venv`;
3. writes the scope (and optional mesh leader) to `/etc/evilkit-os/config.toml`;
4. places the mesh token at `/etc/evilkit-os/mesh-token` (`0600 root:root`, never
   in the manifest);
5. writes `/opt/evilkit-os/manifest.json` as the once-only sentinel.

The systemd unit is `ConditionPathExists=!manifest`, so the bootstrap runs at most
once — a failed first boot retries on the next reboot.

Burn `./cidata` as a NoCloud datasource (an ISO labelled `cidata`, or a
`cloud-init` seed directory), then boot the image. On a raw image with a firstrun
hook (e.g. the Pi drop pattern), place `bootstrap.sh` and the unit by hand.

### Safety properties

- No secret is written into `manifest.json`; the mesh token is the only secret,
  and it lands `0600 root:root`.
- The rendered `user-data` is valid YAML (asserted by a test when PyYAML is
  installed); the rendered `bootstrap.sh` is parsed with `bash -n` in tests.
- `write_seed` validates the spec and refuses whitespace hostnames, a mesh leader
  without a token, and vice-versa.

### Build a Pi drop image

`evilkit appliance build` closes the loop from `seed` to a flashed drop. It
renders the first-boot artifacts (`firstrun.sh`, `cmdline.txt`, `userconf.txt`,
the SSH marker, `authorized_keys`, the mesh token and the baked wheel) and
writes them into the boot partition of a Raspberry Pi OS image — **root-free,
using mtools only**; the ext4 rootfs is never mounted.

```sh
evilkit appliance build \
  --hostname drop01 \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --scope 10.99.50.0/24 \
  --eth0 10.99.50.60/24 --gateway 10.99.50.1 \
  --wifi-ssid lab-net --wifi-psk '...' \
  --mesh-leader http://100.88.148.72:8765 --mesh-token '...' \
  --wheel dist/evilkit_os-2.0.0-py3-none-any.whl \
  --base-image ~/.cache/evilkit-pi/2024-11-19-raspios-bookworm-arm64-lite.img.xz \
  --output ~/images/drop01.img
```

- `--base-image` may be a raw `.img` or an `.img.xz` (decompressed on the fly);
  the base image's own `root=PARTUUID=…` is preserved in `cmdline.txt`.
- `--eth0/--gateway`, `--wifi-ssid/--wifi-psk` and `--mesh-leader/--mesh-token`
  are optional and pairwise — omit a pair to skip that section.
- The driver writes a persistent `OUTPUT.bake/` dir (the rendered artifacts),
  re-reads `firstrun.sh` from the image and `bash -n` checks it, re-reads the
  baked wheel and compares its sha256, then emits `OUTPUT.manifest.md` (no secret
  is ever written to the manifest — the mesh token and Wi-Fi PSK are redacted).
- `--dry-run` renders the bake dir and prints the mtools plan without writing an
  image.

## First fixes in this release

- **Harness credential lock is no longer evadable by a flag.** `ssh -o
  ConnectTimeout=1 root@host` (a flag that takes its own value) now extracts the
  `root` credential and counts toward the L3 cap, where it previously slipped
  through and could not be locked. `_extract_credential` also now recognises
  hostname targets (`ssh root@files01`), not only IPs. `tests/test_harness.py`
  pins both.

## Roadmap

- **Image build** — a `build/` driver that consumes the seed and a base image to
  produce a bootable artifact. The Pi SD-card path (firstrun hook, root-free via
  mtools) is done as `evilkit appliance build`; the NoCloud ISO + `cloud-localds`
  path for cloud-init VM images remains.
- **Heretic/GLM unification** — fold the `evilkit-heretic` / `evilkit-glm53`
  local-model adapters into the single `--model` surface the operator loop already
  uses.
- **Appliance telemetry** — have a booted node report its manifest and first-boot
  result back to the mesh leader, so the fleet is visible on the dashboard.

## Status

`v2.0.0` — first slice. The consolidated core is ported and green; the appliance
seed generator and the harness credential-extraction fix are new in this release.
The Pi image build driver (`evilkit appliance build`) lands on top of `2.0.0`.

## Authorized use

EvilKit OS is a research tool for **authorized security testing only**. You must
own the target, hold written permission to test it, or be operating within an
engagement's defined scope. Testing this repository does not authorize testing
any third-party system — use local fixtures or an environment you are permitted
to test. See `SECURITY.md` for the vulnerability reporting policy.

## License

Source-available under the **EvilKit Commercial License** — see `LICENSE`.
Upstream: [`Bowie1969/evilkit`](https://github.com/Bowie1969/evilkit).

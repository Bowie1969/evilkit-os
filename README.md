# EvilKit OS

The consolidated, evidence-first, scope-gated **operator system** for authorized
AI security testing. EvilKit OS wraps the operator loop (Kimi Code CLI, Qwen, the
heretic/GLM local models), the harness and its circuit breakers, the mission
contract, and the evidence journal into one installable package — and can bake
the whole thing into a bootable drop image with `evilkit appliance`.

This repository is the consolidation of the upstream
[`Bowie1969/evilkit`](https://github.com/Bowie1969/evilkit) control plane into a
single, versioned "OS" release. The core package is ported unchanged and tested;
what is new here is the **appliance** layer and the first fixes below.

## What it is

EvilKit OS is one CLI (`evilkit`) that does four jobs:

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

## First fixes in this release

- **Harness credential lock is no longer evadable by a flag.** `ssh -o
  ConnectTimeout=1 root@host` (a flag that takes its own value) now extracts the
  `root` credential and counts toward the L3 cap, where it previously slipped
  through and could not be locked. `_extract_credential` also now recognises
  hostname targets (`ssh root@files01`), not only IPs. `tests/test_harness.py`
  pins both.

## Roadmap

- **Image build** — a `build/` driver that consumes the seed and a base image URL
  to produce a bootable artifact (NoCloud ISO + `cloud-localds`, or a Pi SD-card
  image with the firstrun hook), closing the loop from `seed` to a flashed drop.
- **Heretic/GLM unification** — fold the `evilkit-heretic` / `evilkit-glm53`
  local-model adapters into the single `--model` surface the operator loop already
  uses.
- **Appliance telemetry** — have a booted node report its manifest and first-boot
  result back to the mesh leader, so the fleet is visible on the dashboard.

## Status

`v2.0.0` — first slice. The consolidated core is ported and green; the appliance
seed generator and the harness credential-extraction fix are new in this release.

## License

MIT — see `LICENSE`. Upstream: `Bowie1969/evilkit`.

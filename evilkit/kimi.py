"""Scoped launcher for the Kimi Code CLI.

``evilkimi`` is the CLI half of the evilkit pair: it gives the Kimi Code CLI the
exact authorised scope in the two places that matter at session start — the
inherited pentest-MCP environment, and the session's agent definition — then
supervises the session.

The Kimi Code CLI has no ``--append-system-prompt`` (the Qwen Code CLI did), so
the system prompt travels in an agent file passed with ``--agent-file``. That
file is rendered per launch into the evilkimi state directory and rewritten with
a handoff brief on every supervised relaunch.

The harness rides along through the CLI's hook events; see ``evilkit.kimihook``
and ``evilkimi install-hooks``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import BRAIN_MODEL, BRAIN_NAME, config as config_mod
from . import mcpscope, prompts, run_profile, scope as scope_mod
from .kernel import EXIT_ERROR, EXIT_OK, EXIT_USAGE, collect_scope as _collect_scope

PROG = "evilkimi"

#: The Kimi Code CLI's own MCP configuration, alongside the project `.mcp.json`.
KIMI_MCP_ENV = "EVILKIMI_KIMI_MCP"

#: Where the rendered agent file and the harness state live.
STATE_ENV = "EVILKIMI_STATE_DIR"


def _out(message: str = "") -> None:
    print(message)


def _warn(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def state_dir() -> Path:
    override = os.environ.get(STATE_ENV)
    if override:
        return Path(os.path.expanduser(override))
    return Path.home() / ".local" / "state" / "evilkimi"


def kimi_home() -> Path:
    """The Kimi Code data root (``KIMI_CODE_HOME`` relocates it)."""
    override = os.environ.get("KIMI_CODE_HOME")
    if override:
        return Path(os.path.expanduser(override))
    return Path.home() / ".kimi-code"


def kimi_user_mcp_path() -> Path:
    """The user-level MCP file the Kimi CLI actually reads."""
    override = os.environ.get(KIMI_MCP_ENV)
    if override:
        return Path(os.path.expanduser(override))
    return kimi_home() / "mcp.json"


def project_root(start: Path | None = None) -> Path | None:
    """Nearest ancestor containing ``.git`` — the CLI's own project-root rule."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        if (directory / ".git").exists():
            return directory
    return None


def kimi_project_mcp_path(start: Path | None = None) -> Path | None:
    """The project-level MCP file, or None outside a repository."""
    root = project_root(start)
    return None if root is None else root / ".kimi-code" / "mcp.json"


def scope_file(start: Path | None = None) -> Path | None:
    """The Kimi MCP file that declares the ``pentest`` server — the one to re-scope.

    The Kimi CLI reads only ``<project>/.kimi-code/mcp.json`` and
    ``$KIMI_CODE_HOME/mcp.json``; a plain ``.mcp.json`` is ignored entirely (verified
    against the running CLI, not inferred). Project level overrides user level by
    server name, so the file that declares the server is the file that controls it.
    """
    for path in (kimi_project_mcp_path(start), kimi_user_mcp_path()):
        if path is not None and path.is_file() and "pentest" in _read_declared_servers(path):
            return path
    return None


def default_model_alias() -> str:
    """The Kimi model alias this variant pins unless the operator overrides it."""
    return f"openrouter/{BRAIN_MODEL}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Launch the Kimi Code CLI with an exact authorised scope baked into the session.",
        epilog=(
            "examples:\n"
            f"  {PROG} -s 10.99.50.0/24,10.50.0.0/24 --allow-unscoped\n"
            f"  {PROG} -s 10.99.50.0/24 --no-write --prompt 'Enumerate services only'\n"
            f"  {PROG} -s 10.99.50.0/24 --allow-unscoped -- --model {default_model_alias()}\n\n"
            "Arguments after -- are passed directly to the Kimi Code CLI.  --allow-unscoped "
            "only permits launch when a project .mcp.json cannot be updated; it does not "
            "remove the scope from Kimi's MCP environment or agent file.\n\n"
            "NOTE: --prompt runs one non-interactive turn (the CLI's -p) and exits. It is "
            "not a pre-sent objective for an interactive session; put the opening task in "
            "the agent file or type it once the session starts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-s", "--scope", metavar="TARGETS", help="comma-separated hosts, IPs or CIDRs")
    parser.add_argument("--mcp-json", metavar="PATH", type=Path, help="optional project .mcp.json to update")
    parser.add_argument("--no-write", action="store_true", help="do not persist the scope to .mcp.json")
    parser.add_argument("-y", "--yes", action="store_true", help="do not prompt; use configured default scope")
    parser.add_argument("-n", "--dry-run", action="store_true", help="show the Kimi launch without starting it")
    parser.add_argument(
        "--allow-unscoped",
        action="store_true",
        help="continue when the requested scope cannot be persisted to .mcp.json",
    )
    parser.add_argument("--allow-any", action="store_true", help="permit a /0 scope")
    parser.add_argument(
        "--model",
        metavar="ALIAS",
        help=f"Kimi model alias for this session (default {default_model_alias()})",
    )
    parser.add_argument(
        "-p",
        "--prompt",
        metavar="TEXT",
        help="one non-interactive turn (the CLI's -p); the session exits afterwards",
    )
    parser.add_argument(
        "--agent-file",
        metavar="PATH",
        type=Path,
        help="write the session agent definition here instead of the evilkimi state directory",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="do not run the MCP/scope preflight checks before launch",
    )
    parser.add_argument(
        "--no-supervise",
        dest="supervise",
        action="store_false",
        help="exec Kimi directly instead of supervising it (no checkpoint/resume)",
    )
    parser.add_argument(
        "--max-restarts",
        type=int,
        default=3,
        metavar="N",
        help="supervised relaunches after an abnormal exit (default 3; 0 disables)",
    )
    parser.add_argument(
        "--resume-brief",
        metavar="PATH",
        type=Path,
        help="file whose contents are appended to the handoff brief on each relaunch",
    )
    parser.add_argument(
        "--dashboard-run-dir",
        type=Path,
        metavar="PATH",
        help="prepared Keystone run directory receiving live session and action telemetry",
    )
    parser.add_argument(
        "--run-profile",
        type=Path,
        metavar="PATH",
        help="TOML/JSON run profile: fixes the scope, the required tools and the "
             "dashboard run, and fails the launch when any of them does not resolve",
    )
    parser.add_argument(
        "--attach-dashboard",
        action="store_true",
        help="declare the lab dashboard's run-control MCP server in the file the Kimi "
             "CLI reads, even when [dashboard] attach is not set in the config",
    )
    parser.add_argument(
        "--no-dashboard-mcp",
        action="store_true",
        help="leave the MCP file alone: this session gets no dashboard run controls",
    )
    parser.add_argument(
        "--window",
        action="store_true",
        help="open this EvilKit clone session in a new desktop terminal window on this box",
    )
    parser.set_defaults(supervise=True)
    return parser


def _kimi_bin(config: config_mod.Config) -> str:
    """Resolve the Kimi Code CLI binary, honouring EVILKIMI_BIN then the config."""
    requested = os.environ.get("EVILKIMI_BIN") or config.resolved_kimi_bin()
    if os.sep in requested:
        return os.path.expanduser(requested)
    found = shutil.which(requested)
    if found:
        return found
    bundled = kimi_home() / "bin" / requested
    return str(bundled) if bundled.is_file() else requested


def _scope_prompt(scope: str) -> str:
    return (
        "AUTHORISED LAB SCOPE — IMMUTABLE FOR THIS SESSION\n"
        f"Exact authorised scope: {scope}\n\n"
        "Before any scanner or security action, initialise the mission once with this exact scope. "
        "Never call set_scope to retry, widen, replace, or repair the scope. A refusal for an "
        "in-scope host is an execution-gate result: inspect it, replan, and do not repeat the "
        "same call. If tools_available reports any scope other than the exact scope above, stop "
        "immediately and report the mismatch. Never bypass a scope mismatch with direct SSH, "
        "a shell, run_command, or another tool. Do not act on hosts outside the exact scope. "
        "Treat tool output as evidence; "
        "do not claim a finding or compromise without it."
    )


def agent_body(scope: str, handoff: str | None = None, briefing: str | None = None) -> str:
    """Render the session agent definition handed to ``--agent-file``.

    The frontmatter is the profile the CLI displays and selects by; the body is
    the system prompt: the scope block, then the stable doctrine, and — when a run
    profile supplies one — the compact range briefing that says what this run
    knows. The briefing is separate on purpose: the doctrine must not carry one
    range's layout into the next run, which is how a stale four-host pivot story
    reached the operator.
    """
    description = (
        f"Scope-gated offensive-security operator for the authorised range {scope} "
        f"(evilkit harness, {BRAIN_NAME})."
    )
    when_to_use = (
        "Use for authorised assessment runs launched by evilkimi; the scope is fixed at "
        "launch and must not be widened or retried."
    )
    parts = [
        "---",
        "name: evilkimi-operator",
        f"description: {json.dumps(description)}",
        f"whenToUse: {json.dumps(when_to_use)}",
        "---",
        "",
        _scope_prompt(scope),
        "",
        prompts.kimi_operator_prompt(scope, briefing=briefing or ""),
    ]
    if handoff:
        parts.extend(["", handoff])
    return "\n".join(parts) + "\n"


def write_agent_file(path: Path, body: str) -> None:
    """Write the agent definition atomically, so a relaunch never sees a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)


def _persist_scope(
    scope: str,
    mcp_path: Path | None,
    config: config_mod.Config,
    *,
    allow_unscoped: bool,
    dry_run: bool,
) -> int:
    """Optionally persist scope while keeping the inherited boundary intact."""
    if mcp_path is None:
        message = (
            f"no Kimi MCP file declares a {mcpscope.SERVER_NAME!r} server (looked in "
            f"{kimi_project_mcp_path()} and {kimi_user_mcp_path()})"
        )
    else:
        try:
            changed = mcpscope.write_scope(
                mcp_path, scope, keep_backups=config.backup_keep, dry_run=dry_run
            )
        except mcpscope.NoPentestServer:
            message = f"{mcp_path} declares no 'pentest' server; scope cannot be persisted there"
        except mcpscope.McpError as exc:
            message = str(exc)
        else:
            if dry_run:
                verb = "would record" if changed else "would leave"
            else:
                verb = "recorded" if changed else "already recorded"
            _out(f"{PROG}: scope {verb} {scope} in {mcp_path}")
            return EXIT_OK

    if not allow_unscoped:
        _warn(message)
        _warn("nothing was launched; pass --allow-unscoped or --no-write to continue")
        return EXIT_ERROR

    _warn(f"{message}; continuing because --allow-unscoped was explicit")
    return EXIT_OK


def _dashboard_mcp_path(args) -> Path:
    """Where to declare the dashboard server: the file the CLI actually reads.

    An explicit ``--mcp-json`` wins. Otherwise the project-level
    ``<root>/.kimi-code/mcp.json``, or the user-level file outside a repository.
    A plain ``.mcp.json`` is never used: the Kimi CLI ignores it, so declaring
    the server there would look attached and start nothing.
    """
    if args.mcp_json is not None:
        return args.mcp_json.expanduser().resolve()
    return kimi_project_mcp_path() or kimi_user_mcp_path()


def _attach_dashboard(args, config: config_mod.Config) -> None:
    """Declare the dashboard run-control MCP server when the launch asked for it.

    Attaching is opt-in (``[dashboard] attach`` or ``--attach-dashboard``) and
    inert without a URL, because the tools' whole authority is reaching that
    board. ``--no-write``, ``--dry-run`` and ``write_mcp_json = false`` all
    report what would happen without touching the file.
    """
    if args.no_dashboard_mcp or not (args.attach_dashboard or config.dashboard.attach):
        return
    if not config.dashboard.enabled():
        _warn("[dashboard] attach is set but no url is; no dashboard run controls this session")
        return
    path = _dashboard_mcp_path(args)
    dry = bool(args.dry_run or args.no_write or not config.write_mcp_json)
    try:
        changed = mcpscope.ensure_dashboard_server(
            path,
            [sys.executable, "-m", "evilkit.dashboard_mcp"],
            keep_backups=config.backup_keep,
            dry_run=dry,
        )
    except mcpscope.McpError as exc:
        _warn(f"could not attach the dashboard MCP server ({exc}); continuing without it")
        return
    if dry:
        _out(f"{PROG}: would {'add' if changed else 'leave'} the dashboard MCP server in {path}")
    elif changed:
        _out(f"{PROG}: dashboard MCP server attached in {path}")
    else:
        _out(f"{PROG}: dashboard MCP server already present in {path}")


def _auto_start_dashboard(config: config_mod.Config, args, *, can_stop: bool) -> bool:
    """Put this launch's run on the board; True when *this* launch started tracking.

    The return value is what the auto-stop guard keys on, and it is true only for
    a control the board reports as **succeeded**: a start refused with "a run is
    already being tracked" means the tracking belongs to someone else, and this
    session must not stop it on its way out.

    ``can_stop`` says whether a process will still be alive when the session ends
    (supervision). Without one the run is still put on the board, with a warning,
    because a launch that asked for tracking is better served by being tracked.
    """
    if args.no_dashboard_mcp or not config.dashboard.auto:
        return False
    if not config.dashboard.enabled():
        _warn("[dashboard] auto is on but no url is set; no run will be put on the board")
        return False
    from . import dashboard_control

    # The client reads the board address from the environment, exactly as the MCP
    # child does — but these calls happen in the launcher's own process, so the
    # config value has to reach it here. An exported value still wins.
    os.environ.setdefault(dashboard_control.URL_ENV, config.dashboard.resolved_url())
    os.environ.setdefault(dashboard_control.TIMEOUT_ENV, f"{config.dashboard.timeout:g}")
    run_dir = getattr(args, "dashboard_run_dir", None)
    if run_dir is not None:
        # So the launcher's own control calls are journalled against the bound
        # run exactly like the session's: _launch_env only sets it for the child.
        os.environ.setdefault(dashboard_control.RUN_DIR_ENV, str(run_dir.expanduser().resolve()))
    try:
        outcome = dashboard_control.auto_start()
    except dashboard_control.DashboardError as exc:
        _warn(f"dashboard: run tracking was not started ({exc})")
        return False
    if not outcome["started"]:
        _out(f"{PROG}: board left alone: {outcome['reason']}")
        return False
    control = outcome["control"]
    verdict = str(control.get("status") or "requested")
    detail = control.get("message") or ""
    if verdict != "succeeded":
        # Either the board refused it outright, or it is still running after the
        # settle window — in both cases this launch does not own the tracking.
        _warn(f"dashboard: run tracking {verdict}{' — ' + detail if detail else ''}")
        return False
    _out(f"{PROG}: run tracking started on the board ({outcome['tracking_before']} before)"
         f"{' — ' + detail if detail else ''}")
    if not can_stop:
        _warn(f"{PROG}: nothing will survive this launch to stop tracking the run it just put "
              "on the board (--no-supervise); stop it from the board or with stop_run")
    return True


def _auto_stop_dashboard(config: config_mod.Config, started_by_us: bool) -> None:
    """Stop tracking the run after the session, if this launch started tracking it."""
    if not (config.dashboard.auto and started_by_us):
        return
    from . import dashboard_control

    try:
        outcome = dashboard_control.auto_stop(started_by_us=True)
    except dashboard_control.DashboardError as exc:
        _warn(f"dashboard: tracking was NOT stopped ({exc}); the board still shows this run")
        return
    control = outcome["control"]
    verdict = str(control.get("status") or "requested")
    detail = control.get("message") or ""
    if verdict == "succeeded":
        _out(f"{PROG}: run tracking stopped on the board{' — ' + detail if detail else ''}")
    else:
        _warn(f"dashboard: run tracking {verdict}{' — ' + detail if detail else ''}")


def _launch_env(
    config: config_mod.Config,
    scope: str,
    model_alias: str,
    dashboard_run_dir: Path | None = None,
) -> dict[str, str]:
    env = dict(os.environ)
    env.update(config.extra_env)
    # Identity so the session is distinguishable in transcripts and the UI.
    env["KIMI_CODE_IDENTITY_NAME"] = os.environ.get("KIMI_CODE_IDENTITY_NAME", PROG)
    env["KIMI_CODE_IDENTITY_SLUG"] = os.environ.get("KIMI_CODE_IDENTITY_SLUG", PROG)
    env["EVILKIMI_SCOPE"] = scope
    env["EVILKIMI_MODEL"] = model_alias
    env["EVILKIT_ENGINE"] = "kimi"
    env[STATE_ENV] = str(state_dir())
    env["EVILKIT_STATE_DIR"] = str(state_dir())
    if dashboard_run_dir is not None:
        env["EVILKIT_DASHBOARD_RUN_DIR"] = str(dashboard_run_dir.expanduser().resolve())
        # Fresh mission ledger per published run. The mission MCP defaults to a
        # shared state file, so without this a run inherits the prior run's
        # findings/flags/witnesses — run 8 started from a 2026-10-13 ledger and
        # had to treat the whole run as contaminated. Keyed by the run id, the
        # ledger is reused across supervised relaunches of the SAME run and
        # starts clean on the next published run. An operator-set
        # CO_MISSION_STATE_PATH always wins.
        mission_dir = state_dir() / "missions"
        mission_dir.mkdir(parents=True, exist_ok=True)
        env.setdefault("CO_MISSION_STATE_PATH", str(mission_dir / f"{dashboard_run_dir.name}.json"))
    # The harness locates its run dir and entry host from these.
    env.setdefault("EVILKIT_ENTRY_HOST", "10.99.50.60")
    # Guest credentials for the malware-scripting MCP's ssh-backed tools. The MCP
    # refuses to run without them — it will not fabricate a deploy, and it will
    # not run a command on its own host and label it remote — so they have to
    # reach the MCP child through the session environment.
    for key, value in config.lab_ssh.resolved().items():
        env[key] = value
    # The provider malware_generate writes code with: the same one the EvilKit
    # operator uses, so the tool does not fall back to a stale hard-coded slug.
    env.setdefault("EVILKIT_OPERATOR_URL", config.brain.resolved_operator_url())
    env.setdefault("EVILKIT_OPERATOR_MODEL", config.brain.resolved_operator_model())
    operator_key = config.brain.resolved_operator_key()
    if operator_key:
        env.setdefault("EVILKIT_OPERATOR_KEY", operator_key)
    # The dashboard's run controls travel in the environment, never in .mcp.json:
    # the URL to call and the timeout to use are per-machine, and the bound run
    # dir the launcher already exports is what end_run finishes. An already
    # exported value wins over the config file.
    dashboard_url = config.dashboard.resolved_url()
    if dashboard_url:
        env.setdefault("EVILKIT_DASHBOARD_URL", dashboard_url)
        env.setdefault("EVILKIT_DASHBOARD_TIMEOUT", f"{config.dashboard.timeout:g}")
    # This reaches Kimi's globally configured MCP child processes even when no
    # project .mcp.json exists. It is deliberately last so config cannot widen it.
    env[mcpscope.SCOPE_ENV_KEY] = scope
    return env


#: The scope gate is enforced only by the pentest server; the rest are optional
#: capabilities whose absence should warn, not block.
REQUIRED_SERVERS = ("pentest",)
OPTIONAL_SERVERS = ("mission", "osint", "wifi", "redteamscripting", "dashboard")

#: Commands that mean "this server runs somewhere else". Their tool list cannot be
#: read from here, so preflight reports them as unconfirmed instead of stalling on
#: a connection to another host.
REMOTE_SERVER_COMMANDS = ("ssh", "docker", "podman")


def _read_declared_servers(path: Path) -> dict:
    """Return the ``mcpServers`` object from a settings/.mcp.json file, or {}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    return servers if isinstance(servers, dict) else {}


def gather_mcp_servers(start: Path | None = None) -> dict:
    """Merge the MCP servers the Kimi CLI will actually load.

    User level first, then project level on top, because a same-name project entry
    overrides the user one. Anything in a plain ``.mcp.json`` is deliberately not
    merged: the CLI does not read that file.
    """
    merged = dict(_read_declared_servers(kimi_user_mcp_path()))
    project = kimi_project_mcp_path(start)
    if project is not None and project.is_file():
        merged.update(_read_declared_servers(project))
    return merged


def legacy_mcp_json(start: Path | None = None) -> Path | None:
    """A plain ``.mcp.json`` at or above the start directory, if there is one.

    Only used to warn about it: the Kimi CLI ignores this file, so a scope recorded
    in one looks enforced and is not.
    """
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".mcp.json"
        if candidate.is_file():
            return candidate
    return None


def _emit_smoke_event(run_dir: Path, entry_host: str, scope: str = "") -> tuple[str, str]:
    """Emit one harmless event and prove the dashboard actually recorded it.

    An emitter that resolves but writes nowhere is the failure that cost two runs
    their entire record, so this writes a real event through the real path and
    then reads it back out of the journal it should have landed in.
    """
    from . import dashboard_telemetry

    marker = "preflight smoke event — no action taken"
    try:
        topology = json.loads((run_dir / "dashboard" / "topology.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ("FAIL", f"could not read the run topology: {exc}")
    addresses = []
    for node in topology.get("nodes", []) if isinstance(topology, dict) else []:
        for field_name in ("ip", "address"):
            addresses.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(node.get(field_name) or "")))
    # The smoke target must differ from the entry host (the emitter deliberately
    # drops an edge whose source and destination are the same node), and it should
    # be inside the run's authorized scope so the smoke event is not painted onto
    # something outside the range.
    targets = [address for address in addresses if address != entry_host]
    in_scope = [address for address in targets if _in_scope(address, scope)]
    if in_scope:
        targets = in_scope
    if not targets:
        return ("FAIL",
                f"the run topology has no second node to record an edge to (only {entry_host}); "
                f"no action in this run could be painted or journalled")

    telemetry = dashboard_telemetry.DashboardTelemetry(run_dir=str(run_dir), entry_host=entry_host)
    event = telemetry.emit_action(f"evilkit run profile: {marker} {targets[0]}", 0,
                                  tool_name="preflight_smoke")
    if not event:
        return ("FAIL",
                f"the dashboard emitter wrote nothing for {run_dir}: its entry host "
                f"{entry_host} or the target is missing from the topology, so every real "
                f"action would be dropped silently")
    journal = run_dir / "journal.jsonl"
    recorded = False
    try:
        for line in journal.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("tool") == "preflight_smoke" and str(record.get("target")) == targets[0]:
                recorded = True
                break
    except OSError:
        recorded = False
    if not recorded:
        return ("FAIL", f"the emitter returned an event but {journal} does not contain it")
    return ("OK", f"dashboard smoke event recorded in {journal.name} (run {run_dir.name}, "
                  f"edge {entry_host} → {targets[0]})")


def _in_scope(address: str, scope: str) -> bool:
    import ipaddress

    try:
        host = ipaddress.ip_address(address)
    except ValueError:
        return False
    for part in (scope or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if host in ipaddress.ip_network(part, strict=False):
                return True
        except ValueError:
            continue
    return False


def preflight(
    scope: str,
    mcp_path: Path | None,
    *,
    wrote_scope: bool,
    profile=None,
    config=None,
) -> tuple[bool, list[tuple[str, str]]]:
    """Check that the scope will actually gate and the expected MCPs are present.

    Returns ``(ok, report)`` where report is a list of ``(level, message)``.
    A FAIL means the run would be unsafe or silently unrecorded; WARN is advisory.

    With a ``profile`` the launch is held to the profile as well: the scope must
    match it, the tools it needs must actually resolve, guest credentials must be
    there if it asks for them, and the dashboard run it names must be able to
    record the entry host — an emitter whose entry host is missing from the
    topology silently drops every event, which is how two runs "recorded nothing".
    """
    report: list[tuple[str, str]] = []
    ok = True

    if not scope:
        report.append(("FAIL", "empty scope — the pentest server treats that as allow-all"))
        ok = False

    servers = gather_mcp_servers()

    for name in REQUIRED_SERVERS:
        if name not in servers:
            report.append(
                ("FAIL", f"no {name!r} MCP server in {kimi_user_mcp_path()} or "
                         f"{kimi_project_mcp_path()}; the CLI would load no pentest server, so "
                         "the scope gate would NOT be enforced")
            )
            ok = False
            continue
        report.append(("OK", f"{name} MCP server declared"))
        server = servers[name]
        command = server.get("command") if isinstance(server, dict) else None
        if command and not (shutil.which(command) or Path(os.path.expanduser(command)).is_file()):
            report.append(("WARN", f"{name} command {command!r} not on PATH — it may fail to start"))

    legacy = legacy_mcp_json()
    if (
        legacy is not None
        and "pentest" in _read_declared_servers(legacy)
        and "pentest" not in servers
    ):
        report.append(
            ("WARN", f"{legacy} declares a pentest server, but the Kimi Code CLI does not read "
                     ".mcp.json — declare it in .kimi-code/mcp.json (or the user-level "
                     f"{kimi_user_mcp_path()}) for the scope to be enforced")
        )

    # That file's pentest env block WINS over the inherited scope, so a stale value
    # there would silently override the launch scope.
    if mcp_path is not None and mcp_path.is_file():
        try:
            file_scope = mcpscope.read_scope(mcp_path)
        except mcpscope.McpError:
            file_scope = None
        if file_scope is not None and file_scope != scope and not wrote_scope:
            report.append(
                ("FAIL", f"{mcp_path} pins pentest scope {file_scope!r}, overriding the launch "
                         f"scope {scope!r}; re-run without --no-write or fix the file")
            )
            ok = False

    missing_optional = [name for name in OPTIONAL_SERVERS if name not in servers]
    if missing_optional:
        report.append(("WARN", f"optional MCP servers not configured: {', '.join(missing_optional)}"))

    if profile is not None:
        profile_ok, profile_report = _profile_preflight(profile, scope, servers, config)
        ok = ok and profile_ok
        report.extend(profile_report)

    return ok, report


def _probe_server_tools(server: dict, timeout: float = 10.0) -> set[str] | None:
    """Ask a locally startable MCP server which tools it advertises.

    Returns None when the server cannot be enumerated from here: it may be
    launched on another host (the pentest MCP is reached over ``ssh``), or its
    command may be missing. That is a WARN, not a failure — and a remote server is
    skipped without waiting, because spawning it just to read its schema costs
    more than the check is worth.
    """
    command = server.get("command")
    if not command or not isinstance(command, str):
        return None
    if os.path.basename(command) in REMOTE_SERVER_COMMANDS:
        return None
    argv = [os.path.expanduser(command)]
    args = server.get("args")
    if isinstance(args, list):
        argv += [str(os.path.expanduser(a)) if isinstance(a, str) else str(a) for a in args]
    if shutil.which(argv[0]) is None and not Path(argv[0]).is_file():
        return None
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    try:
        env = server.get("env") if isinstance(server.get("env"), dict) else {}
        for request in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "evilkit-preflight", "version": "0"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ):
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()
        deadline = time.time() + timeout
        names: set[str] | None = None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == 2:
                tools = (message.get("result") or {}).get("tools") or []
                names = {str(tool.get("name")) for tool in tools if isinstance(tool, dict)}
                break
        return names
    except (OSError, ValueError):
        return None
    finally:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


def _profile_preflight(profile, scope: str, servers: dict, config) -> tuple[bool, list[tuple[str, str]]]:
    """Hold the launch to the run profile. Anything unverifiable fails closed."""
    report: list[tuple[str, str]] = []
    ok = True

    if profile.scope and profile.scope != scope:
        report.append(
            ("FAIL", f"run profile {profile.name!r} authorises {profile.scope!r} but this launch "
                     f"records {scope!r} — a run only compares to another on the same scope")
        )
        ok = False
    else:
        report.append(("OK", f"run profile {profile.name!r} matches the launch scope"))

    for name in profile.required_servers:
        if name not in servers:
            report.append(("FAIL", f"run profile requires the {name!r} MCP server; it is not "
                                   f"declared for the Kimi CLI"))
            ok = False

    if profile.requires_lab_ssh:
        if config is None:
            report.append(("WARN", "profile requires guest credentials but no config was loaded "
                                   "to resolve them"))
        else:
            missing = config.lab_ssh.missing()
            if missing:
                report.append(
                    ("FAIL", "run profile requires guest credentials for the malware tools; "
                             f"{' and '.join(missing)} is not set (add [lab_ssh] to the config "
                             "or export LAB_SSH_*)")
                )
                ok = False
            else:
                report.append(("OK", "guest credentials resolve for the malware tools"))

    needed = list(profile.required_tools)
    if needed:
        found: set[str] = set()
        probed: dict[str, set[str] | None] = {}
        for name, server in sorted(servers.items()):
            if not isinstance(server, dict):
                continue
            probed[name] = _probe_server_tools(server)
            if probed[name] is not None:
                found |= probed[name] or set()
        unprobeable = sorted(name for name, tools in probed.items() if tools is None)

        # A requirement may name the server it belongs to — "pentest:nmap_scan" —
        # which is the only form that can be checked against a server we could not
        # enumerate (the pentest MCP is reached over ssh). A bare tool name is
        # satisfied by any server that advertises it, and can only be proven
        # absent when every server was read.
        missing: list[str] = []
        unconfirmed: list[str] = []
        for entry in needed:
            if ":" in entry:
                server_name, _, tool = entry.partition(":")
                if server_name not in probed:
                    missing.append(entry)
                elif probed[server_name] is None:
                    unconfirmed.append(entry)
                elif tool not in (probed[server_name] or set()):
                    missing.append(entry)
            elif entry in found:
                continue
            elif unprobeable:
                unconfirmed.append(entry)
            else:
                missing.append(entry)

        if missing:
            report.append(
                ("FAIL", f"run profile requires tools no MCP server advertises: "
                         f"{', '.join(missing)}. This is the deferred-tool failure the profile "
                         f"exists to prevent — a refused schema must stop the launch, not a turn.")
            )
            ok = False
        elif unconfirmed:
            report.append(
                ("WARN", f"could not enumerate {', '.join(unprobeable)} to confirm "
                         f"{', '.join(unconfirmed)}; the servers that were readable "
                         f"({', '.join(sorted(n for n, t in probed.items() if t is not None)) or 'none'}) "
                         f"do not advertise them")
            )
        else:
            report.append(("OK", f"required tools resolve: {', '.join(needed)}"))

    if profile.dashboard_run_dir is not None:
        run_dir = profile.dashboard_run_dir
        topology = run_dir / "dashboard" / "topology.json"
        if not run_dir.is_dir():
            report.append(("FAIL", f"dashboard run directory {run_dir} does not exist — the run "
                                   f"would record nothing"))
            ok = False
        elif not topology.is_file():
            report.append(("FAIL", f"{topology} is missing — the dashboard has no topology to "
                                   f"paint the run onto"))
            ok = False
        elif profile.entry_host:
            try:
                nodes = json.loads(topology.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                report.append(("FAIL", f"could not read {topology}: {exc}"))
                ok = False
            else:
                addresses = set()
                for node in nodes.get("nodes", []) if isinstance(nodes, dict) else []:
                    for field_name in ("ip", "address"):
                        value = str(node.get(field_name) or "")
                        addresses.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value))
                if profile.entry_host in addresses:
                    report.append(("OK", f"dashboard can place the entry host {profile.entry_host}"))
                    smoke = _emit_smoke_event(run_dir, profile.entry_host, profile.scope)
                    report.append(smoke)
                else:
                    report.append(
                        ("FAIL", f"the run's topology has no node for the entry host "
                                 f"{profile.entry_host}: every emitted event would be dropped "
                                 f"silently (this is the 'dashboard recorded nothing' failure)")
                    )
                    ok = False

    return ok, report


def write_preflight_report(path: Path, scope: str, report: list[tuple[str, str]],
                           profile=None, ok: bool = True) -> Path:
    """Persist a preflight report beside the run it belongs to."""
    target = Path(os.path.expanduser(str(path)))
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": time.time(),
        "ok": ok,
        "scope": scope,
        "profile": profile.to_dict() if profile is not None else None,
        "report": [{"level": level, "message": message} for level, message in report],
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def _handoff_brief(attempt: int, max_restarts: int, resume_brief_path: Path | None) -> str:
    """Deterministic reorientation appended on a supervised relaunch.

    Directly counters restart-amnesia: re-mapping known hosts and re-trying locked
    credentials after each crash.
    """
    parts = [
        f"SESSION RESUMED — supervised relaunch {attempt} of {max_restarts}.",
        "The previous session exited abnormally. You are continuing the SAME engagement, "
        "not starting over.",
        "Before acting: re-read your own prior findings and notes. Do NOT re-scan hosts you "
        "already enumerated, and do NOT retry any credential that already failed or was locked "
        "— assume prior locks still hold. Resume from the furthest point you reached.",
    ]
    if resume_brief_path is not None:
        try:
            extra = resume_brief_path.read_text(encoding="utf-8").strip()
        except OSError:
            extra = ""
        if extra:
            parts.append("OPERATOR HANDOFF NOTES:\n" + extra)
    return "\n\n".join(parts)


def _supervise(
    kimi: str,
    launch_argv: list[str],
    env: dict[str, str],
    *,
    agent_path: Path,
    scope: str,
    max_restarts: int,
    resume_brief_path: Path | None,
    briefing: str | None = None,
) -> int:
    """Run Kimi as a supervised child, relaunching with a handoff on abnormal exit.

    A clean exit (code 0, e.g. the operator quitting) ends supervision. A crash or
    loop-halt (non-zero) relaunches, up to ``max_restarts``, each time folding a
    handoff brief into the agent file so state is not lost.
    """
    try:
        backoff = max(0.0, float(os.environ.get("EVILKIMI_RESTART_BACKOFF", "3")))
    except ValueError:
        backoff = 3.0
    attempt = 0
    while True:
        handoff = None
        if attempt > 0:
            handoff = _handoff_brief(attempt, max_restarts, resume_brief_path)
            write_agent_file(agent_path, agent_body(scope, handoff, briefing=briefing))
        try:
            proc = subprocess.run([kimi, *launch_argv], env=env)
        except OSError as exc:
            _warn(f"could not start {kimi}: {exc}")
            return EXIT_ERROR
        except KeyboardInterrupt:
            _out(f"{PROG}: interrupted; not relaunching")
            return EXIT_OK

        code = proc.returncode
        if code == 0:
            return EXIT_OK
        if code < 0:
            # Killed by a signal (e.g. the operator Ctrl-C'ing the foreground group).
            # That is a human stop, not a crash — do not fight it with a relaunch.
            _out(f"{PROG}: Kimi stopped by signal {-code}; not relaunching")
            return EXIT_OK
        if attempt >= max_restarts:
            _warn(f"Kimi exited abnormally (code {code}); restart budget ({max_restarts}) exhausted")
            return code if code else EXIT_ERROR
        attempt += 1
        _warn(
            f"Kimi exited abnormally (code {code}); supervised relaunch {attempt}/{max_restarts} "
            f"in {backoff:g}s — Ctrl-C to stop"
        )
        try:
            time.sleep(backoff)
        except KeyboardInterrupt:
            _out(f"{PROG}: interrupted; not relaunching")
            return EXIT_OK


def _kimi_config_path() -> Path:
    return Path.home() / ".kimi-code" / "config.toml"


def _doctor() -> int:
    """Report everything a launch depends on, without launching anything."""
    from . import kimihook

    ok = True
    config, problems = config_mod.load()
    for problem in problems:
        _warn(problem)

    kimi = _kimi_bin(config)
    kimi_found = bool(shutil.which(kimi)) or Path(kimi).is_file()
    _out(f"kimi binary        : {kimi} {'ok' if kimi_found else 'MISSING'}")
    ok &= kimi_found

    alias = os.environ.get("EVILKIMI_MODEL") or default_model_alias()
    config_path = _kimi_config_path()
    declared: set[str] = set()
    try:
        import tomllib

        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        declared = set((data.get("models") or {}).keys())
    except OSError:
        _out(f"kimi config        : {config_path} absent")
    except Exception as exc:  # noqa: BLE001 - report, never crash
        _out(f"kimi config        : {config_path} unreadable ({exc})")
    alias_ok = alias in declared
    if declared:
        _out(f"model alias        : {alias} {'ok' if alias_ok else 'NOT DECLARED in ' + str(config_path)}")
    else:
        _out(f"model alias        : {alias} (cannot verify — no models table found)")
    ok &= alias_ok or not declared

    provider = alias.split("/", 1)[0] if "/" in alias else ""
    if provider:
        key_env = os.environ.get("OPENROUTER_API_KEY", "")
        _out(
            f"provider key       : {provider}/OPENROUTER_API_KEY "
            f"{'set in env' if key_env else 'not in env (must be in config.toml)'}"
        )

    agent_path = state_dir() / "agents" / "evilkimi-operator.md"
    _out(f"agent file         : {agent_path} {'ok' if agent_path.is_file() else 'not written yet'}")

    resolved = scope_file()
    if resolved is None:
        _out("kimi mcp scope file: no Kimi MCP file declares 'pentest' — the scope gate "
             "would not be enforced")
        ok = False
    else:
        _out(f"kimi mcp scope file: {resolved}")
        try:
            _out(f"recorded scope     : {mcpscope.read_scope(resolved) or 'none'}")
        except mcpscope.McpError as exc:
            _out(f"recorded scope     : unreadable ({exc})")
            ok = False

    legacy = legacy_mcp_json()
    if legacy is not None:
        _out(f"legacy .mcp.json   : {legacy} (the Kimi CLI does not read this)")

    servers = gather_mcp_servers()
    _out(f"kimi user mcp      : {kimi_user_mcp_path()}")
    _out(f"kimi project mcp   : {kimi_project_mcp_path() or '(not inside a git repository)'}")
    _out(f"mcp servers seen   : {', '.join(sorted(servers)) or 'none'}")

    hooks_ok = kimihook.hooks_installed(config_path)
    _out(f"harness hooks      : {'installed' if hooks_ok else 'NOT installed (evilkimi install-hooks)'}")
    sessions = sorted((state_dir() / "sessions").glob("*.jsonl"))
    _out(f"harness state      : {state_dir()} ({len(sessions)} session log(s))")
    _out(f"dashboard run dir  : {os.environ.get('EVILKIT_DASHBOARD_RUN_DIR') or '(unset — no telemetry)'}")

    return EXIT_OK if ok else EXIT_ERROR


def _subcommand(name: str) -> int:
    """``evilkimi doctor`` and ``evilkimi install-hooks``, handled before launch flags."""
    from . import kimihook

    if name == "install-hooks":
        changed, message = kimihook.install_hooks(_kimi_config_path())
        _out(f"{PROG}: {message}")
        return EXIT_OK if changed or "already" in message else EXIT_ERROR
    return _doctor()


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in ("doctor", "install-hooks"):
        return _subcommand(raw[0])
    if "--" in raw:
        cut = raw.index("--")
        raw, passthrough = raw[:cut], raw[cut + 1 :]
    else:
        passthrough = []

    args = build_parser().parse_args(raw)
    config, problems = config_mod.load()
    for problem in problems:
        _warn(problem)

    profile = None
    if args.run_profile is not None:
        try:
            profile = run_profile.load_profile(args.run_profile)
        except run_profile.ProfileError as exc:
            _warn(f"run profile rejected: {exc}")
            return EXIT_USAGE
        if args.scope is None and profile.scope:
            args.scope = profile.scope
        if profile.dashboard_run_dir is not None:
            profile_run = profile.dashboard_run_dir.expanduser().resolve()
            if args.dashboard_run_dir is None:
                # The profile is the launch contract, not merely a preflight
                # checklist.  Run 9 validated the profile's dashboard path but
                # launched without exporting it, leaving 139 calls and no
                # scorer journal.  Bind the declared run here so the hook and
                # launch environment use the same directory preflight checked.
                args.dashboard_run_dir = profile_run
            elif args.dashboard_run_dir.expanduser().resolve() != profile_run:
                _warn(
                    "dashboard run mismatch: --dashboard-run-dir resolves to "
                    f"{args.dashboard_run_dir.expanduser().resolve()}, but run profile "
                    f"{profile.name!r} declares {profile_run}"
                )
                return EXIT_USAGE
        _out(f"{PROG}: run profile {profile.name} ({profile.source})")

    scope_from_flag = args.scope is not None
    raw_scope = _collect_scope(args, config)
    try:
        scope = scope_mod.normalise_scope(raw_scope, allow_any=args.allow_any)
    except scope_mod.ScopeError as exc:
        _warn(str(exc))
        _warn("expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'")
        return EXIT_USAGE

    if not scope_from_flag and scope == scope_mod.SOLO_SCOPE:
        _warn("refusing the implicit 127.0.0.1/32 fallback")
        _warn("pass --scope with the exact authorised range, or explicitly pass --scope solo")
        return EXIT_USAGE

    if args.mcp_json is not None:
        explicit = args.mcp_json.expanduser()
        if not explicit.is_file():
            _warn(f"{explicit} does not exist")
            return EXIT_ERROR
        mcp_path: Path | None = explicit.resolve()
    else:
        # Only the file the CLI reads counts: <project>/.kimi-code/mcp.json, else
        # the user-level one. A plain .mcp.json is ignored by the CLI entirely, so
        # scoping one would look enforced and do nothing.
        mcp_path = scope_file()

    if args.no_write:
        _out(f"{PROG}: scope {scope} will not be persisted (--no-write)")
    else:
        code = _persist_scope(
            scope, mcp_path, config, allow_unscoped=args.allow_unscoped, dry_run=args.dry_run
        )
        if code != EXIT_OK:
            return code

    _out(f"{PROG}: inherited MCP scope -> {scope}")
    _attach_dashboard(args, config)

    kimi = _kimi_bin(config)
    if not (Path(kimi).is_file() or shutil.which(kimi)):
        _warn(f"cannot find the Kimi Code CLI ({kimi!r})")
        _warn("install kimi, or set EVILKIMI_BIN (or EVILKIT_KIMI_BIN) to its executable")
        return EXIT_ERROR

    model_alias = args.model or os.environ.get("EVILKIMI_MODEL") or default_model_alias()
    agent_path = (
        args.agent_file.expanduser()
        if args.agent_file is not None
        else state_dir() / "agents" / "evilkimi-operator.md"
    )

    launch_argv: list[str] = ["--agent-file", str(agent_path), "-m", model_alias]
    if args.prompt:
        launch_argv.extend(["-p", args.prompt])
    launch_argv.extend(passthrough)

    if args.dry_run:
        supervised = " (supervised)" if args.supervise and args.max_restarts > 0 else ""
        _out(f"{PROG}: would launch {kimi}{supervised}")
        _out(f"{PROG}: argv -> {' '.join([kimi, *launch_argv])}")
        _out(f"{PROG}: agent file -> {agent_path}")
        _out(f"{PROG}: model alias -> {model_alias}")
        if args.dashboard_run_dir is not None:
            _out(f"{PROG}: dashboard run -> {args.dashboard_run_dir.expanduser().resolve()}")
        return EXIT_OK

    if args.dashboard_run_dir is not None:
        from . import kimihook

        topology = args.dashboard_run_dir.expanduser() / "dashboard" / "topology.json"
        if not topology.is_file():
            _warn(f"dashboard topology is missing: {topology}")
            return EXIT_ERROR
        if not kimihook.hooks_installed(_kimi_config_path()):
            _warn("Kimi hooks are not installed; run `evilkit hooks install --engine kimi`")
            return EXIT_ERROR

    if not args.skip_preflight:
        ok, report = preflight(
            scope, mcp_path, wrote_scope=(not args.no_write and mcp_path is not None),
            profile=profile, config=config,
        )
        for level, message in report:
            (_out if level == "OK" else _warn)(f"{PROG}: [{level}] {message}")
        if profile is not None:
            if profile.trace_path is not None:
                report_path = profile.trace_path.with_suffix(".preflight.json")
            else:
                slug = re.sub(r"[^A-Za-z0-9]+", "_", scope).strip("_") or "scope"
                report_path = state_dir() / "preflight" / f"{slug}.json"
            try:
                _out(f"{PROG}: preflight report -> "
                     f"{write_preflight_report(report_path, scope, report, profile, ok)}")
            except OSError as exc:
                _warn(f"could not write the preflight report: {exc}")
        if not ok:
            _warn("preflight failed; fix the above or pass --skip-preflight to override")
            return EXIT_ERROR

    write_agent_file(agent_path, agent_body(scope, briefing=profile.briefing() if profile else None))
    _out(f"{PROG}: authorised scope -> {scope}")
    sys.stdout.flush()
    sys.stderr.flush()
    env = _launch_env(config, scope, model_alias, args.dashboard_run_dir)

    if getattr(args, "window", False):
        from .terminal_window import spawn_terminal_window

        inner_raw = [a for a in raw if a != "--window"]
        if passthrough:
            inner_raw.extend(["--", *passthrough])
        proc = spawn_terminal_window(
            [sys.executable, "-m", "evilkit.kimi", *inner_raw],
            title=f"EvilKit Kimi ({scope})",
            hold=bool(args.prompt),
            cwd=Path.cwd(),
            env=env,
        )
        if proc is None:
            _warn("cannot open a terminal window (no display or terminal emulator found)")
            return EXIT_ERROR
        _out(f"{PROG}: opened terminal window (pid {proc.pid})")
        return EXIT_OK

    supervised = bool(args.supervise and args.max_restarts > 0)
    started_by_us = _auto_start_dashboard(config, args, can_stop=supervised)
    # Without this the banner sits in the buffer while the session writes straight
    # to the terminal, so a piped launch reads as if the board was touched after
    # the session rather than before it.
    sys.stdout.flush()
    sys.stderr.flush()

    if supervised:
        try:
            return _supervise(
                kimi, launch_argv, env,
                agent_path=agent_path, scope=scope,
                max_restarts=args.max_restarts, resume_brief_path=args.resume_brief,
                briefing=profile.briefing() if profile else None,
            )
        finally:
            _auto_stop_dashboard(config, started_by_us)

    if started_by_us:
        _warn(f"{PROG}: --no-supervise means nothing survives to stop tracking the run this "
              "launch put on the board; stop it from the board or with stop_run")
    try:
        os.execvpe(kimi, [kimi, *launch_argv], env)
    except OSError as exc:
        _warn(f"could not start {kimi}: {exc}")
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

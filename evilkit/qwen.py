"""Scoped launcher for the Qwen Code CLI.

``evilqwen`` is intentionally a small adapter rather than a second agent
implementation.  It gives Qwen the exact authorised scope in both places that
matter at session start: the inherited pentest-MCP environment and an appended
system prompt.  The prompt tells Qwen to initialise the mission once, instead
of trying to repair a tool refusal by repeatedly changing scope.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import config as config_mod
from . import mcpscope, prompts, scope as scope_mod
from .kernel import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    collect_scope as _collect_scope,
    resolve_mcp_path as _resolve_mcp_path,
)

PROG = "evilqwen"


def _out(message: str = "") -> None:
    print(message)


def _warn(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Launch Qwen Code with an exact authorised scope baked into the session.",
        epilog=(
            "examples:\n"
            "  evilqwen -s 10.99.50.0/24,10.50.0.0/24 --allow-unscoped\n"
            "  evilqwen -s 10.99.50.0/24 --no-write --prompt 'Enumerate services only'\n"
            "  evilqwen -s 10.99.50.0/24 --allow-unscoped -- --model qwen-3-6-plus\n\n"
            "Arguments after -- are passed directly to Qwen Code.  --allow-unscoped "
            "only permits launch when a project .mcp.json cannot be updated; it "
            "does not remove the scope from Qwen's MCP environment or prompt."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-s", "--scope", metavar="TARGETS", help="comma-separated hosts, IPs or CIDRs")
    parser.add_argument("--mcp-json", metavar="PATH", type=Path, help="optional project .mcp.json to update")
    parser.add_argument("--no-write", action="store_true", help="do not persist the scope to .mcp.json")
    parser.add_argument("-y", "--yes", action="store_true", help="do not prompt; use configured default scope")
    parser.add_argument("-n", "--dry-run", action="store_true", help="show the Qwen launch without starting it")
    parser.add_argument(
        "--allow-unscoped",
        action="store_true",
        help="continue when the requested scope cannot be persisted to .mcp.json",
    )
    parser.add_argument("--allow-any", action="store_true", help="permit a /0 scope")
    parser.add_argument(
        "--prompt",
        metavar="TEXT",
        help="opening task for Qwen; Qwen remains interactive after receiving it",
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
        help="exec Qwen directly instead of supervising it (no checkpoint/resume)",
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
        "--attach-dashboard",
        action="store_true",
        help="declare the lab dashboard's run-control MCP server in the project .mcp.json, "
             "even when [dashboard] attach is not set in the config",
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


def _qwen_bin() -> str:
    """Resolve Qwen without reusing the Kimi-specific EvilKit configuration."""
    requested = os.environ.get("EVILQWEN_BIN") or os.environ.get("EVILKIT_QWEN_BIN") or "qwen"
    if os.sep in requested:
        return os.path.expanduser(requested)
    return shutil.which(requested) or requested


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


def _persist_scope(
    scope: str,
    mcp_path: Path | None,
    config: config_mod.Config,
    *,
    allow_unscoped: bool,
    dry_run: bool,
) -> int:
    """Optionally persist scope while keeping the inherited Qwen boundary intact."""
    if mcp_path is None:
        message = "no project .mcp.json found; scope cannot be persisted there"
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


def _attach_dashboard(args, config: config_mod.Config, mcp_path: Path | None) -> None:
    """Declare the dashboard run-control MCP server when the launch asked for it.

    The Qwen adapter reads the project ``.mcp.json`` (see ``_gather_mcp_servers``),
    so that is where the server is declared. Without one there is nowhere to put
    it and the session simply has no run controls. Attaching is opt-in, inert
    without a URL, and reported rather than written under ``--dry-run``,
    ``--no-write`` or ``write_mcp_json = false``.
    """
    if args.no_dashboard_mcp or not (args.attach_dashboard or config.dashboard.attach):
        return
    if not config.dashboard.enabled():
        _warn("[dashboard] attach is set but no url is; no dashboard run controls this session")
        return
    if mcp_path is None:
        _warn("dashboard: no project .mcp.json found; the session will not have the run controls")
        return
    dry = bool(args.dry_run or args.no_write or not config.write_mcp_json)
    try:
        changed = mcpscope.ensure_dashboard_server(
            mcp_path,
            [sys.executable, "-m", "evilkit.dashboard_mcp"],
            keep_backups=config.backup_keep,
            dry_run=dry,
        )
    except mcpscope.McpError as exc:
        _warn(f"dashboard: could not attach the MCP server ({exc}); continuing without it")
        return
    if dry:
        _out(f"{PROG}: would {'add' if changed else 'leave'} the dashboard MCP server in {mcp_path}")
    elif changed:
        _out(f"{PROG}: dashboard MCP server attached in {mcp_path}")
    else:
        _out(f"{PROG}: dashboard MCP server already present in {mcp_path}")


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
    dashboard_run_dir: Path | None = None,
) -> dict[str, str]:
    env = dict(os.environ)
    env.update(config.extra_env)
    # This reaches Qwen's globally configured MCP child processes even when no
    # project .mcp.json exists.  It is deliberately last so config cannot widen it.
    env[mcpscope.SCOPE_ENV_KEY] = scope
    env["EVILQWEN_SCOPE"] = scope
    env["EVILKIT_ENGINE"] = "qwen"
    if dashboard_run_dir is not None:
        env["EVILKIT_DASHBOARD_RUN_DIR"] = str(dashboard_run_dir.expanduser().resolve())
    # The dashboard's run controls travel in the environment, never in .mcp.json:
    # the URL to call and the timeout to use are per-machine, and the bound run
    # dir above is what end_run finishes.  An already exported value wins.
    dashboard_url = config.dashboard.resolved_url()
    if dashboard_url:
        env.setdefault("EVILKIT_DASHBOARD_URL", dashboard_url)
        env.setdefault("EVILKIT_DASHBOARD_TIMEOUT", f"{config.dashboard.timeout:g}")
    return env


#: The scope gate is enforced only by the pentest server; the rest are optional
#: capabilities whose absence should warn, not block.
REQUIRED_SERVERS = ("pentest",)
OPTIONAL_SERVERS = ("mission", "wifi", "redteamscripting", "osint", "dashboard")


def _qwen_settings_path() -> Path:
    raw = os.environ.get("EVILQWEN_SETTINGS") or "~/.qwen/settings.json"
    return Path(os.path.expanduser(raw))


def _read_declared_servers(path: Path) -> dict:
    """Return the ``mcpServers`` object from a settings/.mcp.json file, or {}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    return servers if isinstance(servers, dict) else {}


def _gather_mcp_servers(mcp_path: Path | None) -> dict:
    """Merge MCP servers from the user Qwen settings and the project .mcp.json."""
    merged = dict(_read_declared_servers(_qwen_settings_path()))
    if mcp_path is not None and mcp_path.is_file():
        merged.update(_read_declared_servers(mcp_path))
    return merged


def _preflight(
    scope: str, mcp_path: Path | None, *, wrote_scope: bool
) -> tuple[bool, list[tuple[str, str]]]:
    """Check that the scope will actually gate and the expected MCPs are present.

    Returns ``(ok, report)`` where report is a list of ``(level, message)``.
    A FAIL means the run would be unsafe or silently unrecorded; WARN is advisory.
    """
    report: list[tuple[str, str]] = []
    ok = True

    if not scope:
        report.append(("FAIL", "empty scope — the pentest server treats that as allow-all"))
        ok = False

    servers = _gather_mcp_servers(mcp_path)

    for name in REQUIRED_SERVERS:
        if name not in servers:
            report.append(
                ("FAIL", f"no {name!r} MCP server in .mcp.json or {_qwen_settings_path()}; "
                         "the scope gate would NOT be enforced")
            )
            ok = False
            continue
        report.append(("OK", f"{name} MCP server declared"))
        server = servers[name]
        command = server.get("command") if isinstance(server, dict) else None
        if command and not (shutil.which(command) or Path(os.path.expanduser(command)).is_file()):
            report.append(("WARN", f"{name} command {command!r} not on PATH — it may fail to start"))

    # A project .mcp.json pentest env block WINS over the inherited scope, so a
    # stale value there would silently override the launch scope.
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

    return ok, report


def _handoff_brief(attempt: int, max_restarts: int, resume_brief_path: Path | None) -> str:
    """Deterministic reorientation appended on a supervised relaunch.

    Directly counters the measured restart-amnesia: re-nmapping known hosts and
    re-trying locked credentials after each crash.
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
    qwen: str,
    appended_prompt: str,
    tail_args: list[str],
    env: dict[str, str],
    *,
    max_restarts: int,
    resume_brief_path: Path | None,
) -> int:
    """Run Qwen as a supervised child, relaunching with a handoff on abnormal exit.

    A clean exit (code 0, e.g. the operator quitting) ends supervision. A crash or
    loop-halt (non-zero) relaunches, up to ``max_restarts``, each time folding a
    handoff brief into the single ``--append-system-prompt`` so state is not lost.
    """
    try:
        backoff = max(0.0, float(os.environ.get("EVILQWEN_RESTART_BACKOFF", "3")))
    except ValueError:
        backoff = 3.0
    attempt = 0
    while True:
        prompt = appended_prompt
        if attempt > 0:
            prompt = appended_prompt + "\n\n" + _handoff_brief(attempt, max_restarts, resume_brief_path)
        argv = [qwen, "--append-system-prompt", prompt, *tail_args]
        try:
            proc = subprocess.run(argv, env=env)
        except OSError as exc:
            _warn(f"could not start {qwen}: {exc}")
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
            _out(f"{PROG}: Qwen stopped by signal {-code}; not relaunching")
            return EXIT_OK
        if attempt >= max_restarts:
            _warn(f"Qwen exited abnormally (code {code}); restart budget ({max_restarts}) exhausted")
            return code if code else EXIT_ERROR
        attempt += 1
        _warn(
            f"Qwen exited abnormally (code {code}); supervised relaunch {attempt}/{max_restarts} "
            f"in {backoff:g}s — Ctrl-C to stop"
        )
        try:
            time.sleep(backoff)
        except KeyboardInterrupt:
            _out(f"{PROG}: interrupted; not relaunching")
            return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--" in raw:
        cut = raw.index("--")
        raw, passthrough = raw[:cut], raw[cut + 1 :]
    else:
        passthrough = []

    args = build_parser().parse_args(raw)
    config, problems = config_mod.load()
    for problem in problems:
        _warn(problem)

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

    try:
        mcp_path = _resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        _warn(str(exc))
        return EXIT_ERROR

    if args.no_write:
        _out(f"{PROG}: scope {scope} will not be persisted (--no-write)")
    else:
        code = _persist_scope(
            scope, mcp_path, config, allow_unscoped=args.allow_unscoped, dry_run=args.dry_run
        )
        if code != EXIT_OK:
            return code

    _out(f"{PROG}: inherited MCP scope -> {scope}")
    _attach_dashboard(args, config, mcp_path)

    qwen = _qwen_bin()
    if not (Path(qwen).is_file() or shutil.which(qwen)):
        _warn(f"cannot find the Qwen Code CLI ({qwen!r})")
        _warn("install qwen, or set EVILQWEN_BIN to its executable")
        return EXIT_ERROR

    appended_prompt = _scope_prompt(scope) + "\n\n" + prompts.evilqwen_operator_prompt(scope)
    tail_args: list[str] = []
    if args.prompt:
        tail_args.extend(["--prompt-interactive", args.prompt])
    tail_args.extend(passthrough)
    child_args = ["--append-system-prompt", appended_prompt, *tail_args]

    if args.dry_run:
        supervised = " (supervised)" if args.supervise and args.max_restarts > 0 else ""
        _out(f"{PROG}: would launch {qwen} with scoped Qwen instructions{supervised}")
        return EXIT_OK

    if args.dashboard_run_dir is not None:
        from . import qwenhooks

        topology = args.dashboard_run_dir.expanduser() / "dashboard" / "topology.json"
        if not topology.is_file():
            _warn(f"dashboard topology is missing: {topology}")
            return EXIT_ERROR
        if not qwenhooks.hooks_installed():
            _warn("Qwen hooks are not installed; run `evilkit hooks install --engine qwen`")
            return EXIT_ERROR

    if not args.skip_preflight:
        ok, report = _preflight(
            scope, mcp_path, wrote_scope=(not args.no_write and mcp_path is not None)
        )
        for level, message in report:
            (_out if level == "OK" else _warn)(f"{PROG}: [{level}] {message}")
        if not ok:
            _warn("preflight failed; fix the above or pass --skip-preflight to override")
            return EXIT_ERROR

    _out(f"{PROG}: authorised scope -> {scope}")
    sys.stdout.flush()
    sys.stderr.flush()
    env = _launch_env(config, scope, args.dashboard_run_dir)

    if getattr(args, "window", False):
        from .terminal_window import spawn_terminal_window

        inner_raw = [a for a in raw if a != "--window"]
        if passthrough:
            inner_raw.extend(["--", *passthrough])
        proc = spawn_terminal_window(
            [sys.executable, "-m", "evilkit.qwen", *inner_raw],
            title=f"EvilKit Qwen ({scope})",
            hold=False,
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
                qwen, appended_prompt, tail_args, env,
                max_restarts=args.max_restarts, resume_brief_path=args.resume_brief,
            )
        finally:
            _auto_stop_dashboard(config, started_by_us)

    if started_by_us:
        _warn(f"{PROG}: --no-supervise means nothing survives to stop tracking the run this "
              "launch put on the board; stop it from the board or with stop_run")
    try:
        os.execvpe(qwen, [qwen, *child_args], env)
    except OSError as exc:
        _warn(f"could not start {qwen}: {exc}")
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

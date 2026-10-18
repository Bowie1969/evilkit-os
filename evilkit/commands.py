"""Command implementations for the EvilKit CLI.

Each ``cmd_*`` function takes the parsed argparse namespace, the resolved
configuration, and the list of config problems, then returns an exit code.
Output is written directly to stdout/stderr to keep the layer thin.
"""

from __future__ import annotations

import os
import json
import shlex
import shutil
import sys
import time
from pathlib import Path

from . import agent as agent_mod
from . import appliance as appliance_mod
from . import audit as audit_mod
from . import build as build_mod
from . import call_taxonomy as taxonomy_mod
from . import config as config_mod
from . import mcpscope
from . import osint as osint_mod
from . import patch_diff_poc as pdp_mod
from . import scope as scope_mod
from . import script_harness as script_harness_mod
from . import theme as theme_mod
from . import watch as watch_mod
from .kernel import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    PROG,
    apply_scope,
    audit_path,
    collect_scope,
    launch_env,
    record_launch,
    resolve_kimi_bin,
    resolve_mcp_path,
    split_seeds,
    split_tools,
)

__all__ = [
    "cmd_run",
    "cmd_scope",
    "cmd_log",
    "cmd_watch",
    "cmd_doctor",
    "cmd_theme",
    "cmd_config",
    "cmd_agent",
    "cmd_osint",
    "cmd_patch_diff_poc",
    "cmd_appliance",
    "cmd_appliance_build",
    "cmd_lessons",
    "cmd_learn",
    "cmd_hooks",
    "cmd_dashboard",
]

#: Findings rows shown in the interactive selection; the JSON file always
#: holds everything, and --osint-accept matches against the full set.
OSINT_DISPLAY_LIMIT = 50

#: Scope actions that change the record without launching anything.
_SCOPE_EDITORS = frozenset({"set", "add", "remove"})


def _format_entry(entry: dict) -> str:
    """Render one log entry as a single readable line."""
    at = str(entry.get("at", "?"))
    scope = str(entry.get("scope", "?"))
    state = "enforced" if entry.get("enforced") else "NOT enforced"
    target = entry.get("mcp_json") or "-"
    return f"{at}  {scope}  {state}  {target}"


# ------------------------------------------------------------------ run


def _osint_stage_and_select(args, config: config_mod.Config) -> int | None:
    """Run the optional --osint stage and let the operator pick the scope.

    Returns an exit code to bail out with, or None on success once ``args.scope``
    carries the operator's selection.
    """
    seeds = split_seeds(args.osint)
    if not seeds:
        print(f"{PROG}: --osint needs at least one seed (domain, email, username, IP or phone)", file=sys.stderr)
        return EXIT_USAGE

    interactive = not args.yes and sys.stdin.isatty() and args.osint_accept is None
    if args.osint_accept is None and not interactive:
        print(
            f"{PROG}: --osint chooses the scope interactively; pass --osint-accept "
            "\"value1,value2\" to run without a prompt",
            file=sys.stderr,
        )
        return EXIT_USAGE

    def _event(message: str) -> None:
        print(f"{PROG}: osint {message}")

    try:
        findings = osint_mod.run_stage(
            seeds,
            python_bin=config.osint.resolved_python(),
            script=config.osint.resolved_script(),
            timeout_each=config.osint.timeout_each,
            on_event=_event,
        )
    except osint_mod.McpConnectionError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        print(
            "nothing was launched; check `evilkit doctor` and the [osint] config table",
            file=sys.stderr,
        )
        return EXIT_ERROR

    findings_path = Path.cwd() / "osint-findings.json"
    try:
        osint_mod.write_findings(findings, findings_path)
        print(f"{PROG}: osint findings -> {findings_path}")
    except OSError as exc:
        print(f"{PROG}: osint: could not write {findings_path}: {exc}", file=sys.stderr)

    rows = osint_mod.candidate_table(findings)
    display = rows[:OSINT_DISPLAY_LIMIT]
    print()
    print("OSINT findings:")
    for number, value, kind, sources, eligible in display:
        suffix = "" if eligible else "   (not scope-eligible)"
        print(f"  {number:>3}  {value:<44} {kind:<9} [{sources}]{suffix}")
    if len(rows) > len(display):
        print(f"  ... {len(rows) - len(display)} more candidates in the findings file")
    print()

    if args.osint_accept is not None:
        accept_values = [v.strip() for v in args.osint_accept.split(",") if v.strip()]
        print(f"{PROG}: osint --osint-accept -> {args.osint_accept}")
        by_value: dict[str, tuple] = {}
        for row in rows:
            by_value.setdefault(row[1].lower(), row)
        picks: list[tuple] = []
        for value in accept_values:
            row = by_value.get(value.lower())
            if row is None:
                print(f"{PROG}: osint: {value!r} is not among the findings; skipped", file=sys.stderr)
                continue
            picks.append(row)
    else:
        try:
            chosen_text = input(
                "select scope candidates (numbers or 1,3-5; 'a' = all shown; "
                "enter = abort)> "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            chosen_text = ""
        print()

        picked = osint_mod.parse_selection(chosen_text, len(display))
        if picked is None:
            print("aborted: nothing recorded, nothing launched", file=sys.stderr)
            return EXIT_ERROR
        picks = [display[number - 1] for number in picked]

    if not picks:
        print("no valid selection: nothing recorded or launched", file=sys.stderr)
        return EXIT_ERROR

    values: list[str] = []
    for number, value, kind, _sources, eligible in picks:
        if not eligible:
            print(
                f"{PROG}: candidate {number} ({value}) is data about a person or platform, "
                "not something to authorise; skipped",
                file=sys.stderr,
            )
            continue
        try:
            token = scope_mod.normalise_scope(value)
        except scope_mod.ScopeError as exc:
            print(
                f"{PROG}: candidate {number} ({value}) rejected by the scope parser ({exc}); skipped",
                file=sys.stderr,
            )
            continue
        if token not in values:
            values.append(token)

    if not values:
        print(
            "nothing picked could be authorised as a scope: nothing recorded or launched",
            file=sys.stderr,
        )
        print(
            "emails, usernames, phones and breach names are data ABOUT you, not hosts; "
            "they can never be targets",
            file=sys.stderr,
        )
        if picks:
            print(
                f"your {len(picks)} pick(s) were all in that category; re-run with a domain "
                "you own added to the seeds, or skip the OSINT stage and run "
                "`evilkit -s <host-you-own>` directly",
                file=sys.stderr,
            )
        return EXIT_ERROR

    args.scope = ",".join(values)
    print(f"{PROG}: osint selection -> {args.scope}")
    return None


def cmd_run(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    if getattr(args, "osint", None) is not None:
        code = _osint_stage_and_select(args, config)
        if code is not None:
            return code

    raw_scope = collect_scope(args, config)

    try:
        mcp_path = resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    write = not args.no_write and config.write_mcp_json

    if getattr(args, "osint", None) is not None and not args.no_osint_mcp:
        attach_dry = bool(args.dry_run or args.no_write or not write)
        if mcp_path is None:
            if not attach_dry:
                print(
                    f"{PROG}: osint: no .mcp.json found; the session will not have the "
                    "osint MCP server",
                    file=sys.stderr,
                )
        else:
            try:
                changed = mcpscope.ensure_osint_server(
                    mcp_path,
                    [config.osint.resolved_python(), config.osint.resolved_script()],
                    keep_backups=config.backup_keep,
                    dry_run=attach_dry,
                )
            except mcpscope.McpError as exc:
                print(
                    f"{PROG}: osint: could not attach the osint MCP server ({exc}); "
                    "continuing without it",
                    file=sys.stderr,
                )
            else:
                if attach_dry:
                    state = "add" if changed else "leave"
                    print(f"{PROG}: would {state} the osint MCP server in {mcp_path}")
                elif changed:
                    print(f"{PROG}: osint MCP server attached in {mcp_path}")
                else:
                    print(f"{PROG}: osint MCP server already present in {mcp_path}")

    if args.dry_run:
        normalised, code, _ = apply_scope(
            raw_scope,
            mcp_path,
            config,
            write=write,
            allow_unscoped=args.allow_unscoped,
            allow_any=args.allow_any,
            dry_run=True,
            deny_text=args.deny,
        )
        if code != EXIT_OK:
            return code
        print(f"{PROG}: would launch {resolve_kimi_bin(config)}")
        return EXIT_OK

    kimi = resolve_kimi_bin(config)
    if not (Path(kimi).is_file() or shutil.which(kimi)):
        print(f"{PROG}: cannot find the Kimi Code CLI ({kimi!r})", file=sys.stderr)
        print("install it, or set kimi_bin in your config, or export EVILKIT_KIMI_BIN", file=sys.stderr)
        return EXIT_ERROR

    normalised, code, enforced = apply_scope(
        raw_scope,
        mcp_path,
        config,
        write=write,
        allow_unscoped=args.allow_unscoped,
        allow_any=args.allow_any,
        deny_text=args.deny,
    )
    if code != EXIT_OK:
        return code

    record_launch(
        config,
        normalised,
        enforced=enforced,
        mcp_path=mcp_path,
        kimi=kimi,
        no_audit=args.no_audit,
    )

    passthrough = list(args.passthrough or [])
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]

    if enforced:
        print(f"{PROG}: authorized scope -> {normalised}")
    else:
        print(f"{PROG}: scope -> {normalised} (NOT enforced; recorded scope is unchanged)")
    env = launch_env(config, normalised)
    sys.stdout.flush()
    sys.stderr.flush()
    if getattr(args, "window", False):
        from .terminal_window import spawn_terminal_window

        proc = spawn_terminal_window(
            [kimi, *passthrough],
            title=f"EvilKit ({normalised})",
            hold=False,
            cwd=Path.cwd(),
            env=env,
        )
        if proc is None:
            print(f"{PROG}: cannot open a terminal window (no display or terminal emulator found)", file=sys.stderr)
            return EXIT_ERROR
        print(f"{PROG}: opened terminal window (pid {proc.pid})")
        return EXIT_OK
    try:
        os.execvpe(kimi, [kimi, *passthrough], env)
    except OSError as exc:
        print(f"{PROG}: could not start {kimi}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


# ------------------------------------------------------------------ scope


def _merge_scope(action: str, recorded: list[str], requested: list[str]) -> list[str]:
    """Fold ``requested`` into ``recorded`` for an add or a remove."""
    if action == "add":
        known = set(recorded)
        return [*recorded, *(token for token in requested if token not in known)]
    dropped = set(requested)
    return [token for token in recorded if token not in dropped]


def _edit_scope(action: str, args, config: config_mod.Config, mcp_path: Path) -> int:
    """Change the recorded scope in place, without launching the CLI."""
    try:
        requested = scope_mod.parse_scope(args.targets, allow_any=args.allow_any)
    except scope_mod.ScopeError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        print("expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'", file=sys.stderr)
        return EXIT_USAGE

    if action == "set":
        merged = list(requested)
    else:
        try:
            current = mcpscope.read_scope(mcp_path)
        except mcpscope.McpError as exc:
            print(f"{PROG}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if current is None:
            if action == "remove":
                print(f"{PROG}: nothing to remove: no scope is recorded in {mcp_path}", file=sys.stderr)
                return EXIT_ERROR
            recorded: list[str] = []
        else:
            try:
                recorded = scope_mod.parse_scope(current, allow_any=True)
            except scope_mod.ScopeError as exc:
                print(
                    f"{PROG}: the scope recorded in {mcp_path} cannot be merged: {exc}",
                    file=sys.stderr,
                )
                print("use 'evilkit scope set' to replace it", file=sys.stderr)
                return EXIT_ERROR
        merged = _merge_scope(action, recorded, requested)

    if not merged:
        print("that would leave no target at all; the record was left alone", file=sys.stderr)
        print("use 'evilkit scope clear' to reset to the locked-down default", file=sys.stderr)
        return EXIT_ERROR

    target = ",".join(merged)
    try:
        changed = mcpscope.write_scope(
            mcp_path, target, keep_backups=config.backup_keep, dry_run=args.dry_run
        )
    except mcpscope.McpError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.dry_run:
        if changed:
            print(f"{PROG}: would record {target} in {mcp_path}")
        else:
            print(f"{PROG}: would leave {mcp_path} at {target}")
    elif changed:
        print(f"{PROG}: scope {target} recorded in {mcp_path}")
    else:
        print(f"{PROG}: scope already {target} in {mcp_path}")
    return EXIT_OK


def cmd_scope(args, config: config_mod.Config) -> int:
    action = args.scope_command or "show"
    try:
        mcp_path = resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if mcp_path is None:
        print("no .mcp.json found", file=sys.stderr)
        return EXIT_ERROR

    if action in _SCOPE_EDITORS:
        return _edit_scope(action, args, config, mcp_path)

    if action == "clear":
        target = scope_mod.SOLO_SCOPE
        try:
            changed = mcpscope.write_scope(mcp_path, target, keep_backups=config.backup_keep)
        except mcpscope.McpError as exc:
            print(f"{PROG}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        verb = "reset to" if changed else "already"
        print(f"{PROG}: {mcp_path} {verb} {target}")
        return EXIT_OK

    try:
        current = mcpscope.read_scope(mcp_path)
        denied = mcpscope.read_deny(mcp_path)
    except mcpscope.McpError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if current is None:
        print(f"{PROG}: {mcp_path} declares no pentest server", file=sys.stderr)
        return EXIT_ERROR
    print(current)
    if denied:
        print(f"deny: {denied}")
    return EXIT_OK


# ------------------------------------------------------------------ log


def cmd_log(args, config: config_mod.Config) -> int:
    path = args.path.expanduser() if args.path is not None else audit_path(config)
    limit = args.limit if args.limit and args.limit > 0 else None

    try:
        entries, skipped = audit_mod.read(path, limit)
    except audit_mod.LogError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not entries:
        if skipped:
            print(f"{PROG}: {path} holds no readable entries; {skipped} line(s) were skipped", file=sys.stderr)
            return EXIT_ERROR
        print(f"{PROG}: no launches recorded yet ({path})")
        return EXIT_OK

    if args.json:
        for entry in entries:
            print(audit_mod.to_line(entry))
    else:
        for entry in reversed(entries):
            print(_format_entry(entry))

    if skipped:
        print(f"{PROG}: {skipped} unreadable line(s) in {path} were skipped", file=sys.stderr)
    return EXIT_OK


# ------------------------------------------------------------------ watch


def _read_launches(path: Path, limit: int) -> tuple[list[dict], str]:
    """The newest ``limit`` entries, and a note when the log cannot be read."""
    if limit <= 0:
        return [], ""
    try:
        entries, skipped = audit_mod.read(path, limit)
    except audit_mod.LogError as exc:
        return [], f"log unreadable ({exc})"
    return entries, (f"{skipped} unreadable line(s) skipped" if skipped else "")


def cmd_watch(args, config: config_mod.Config) -> int:
    try:
        mcp_path = resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if mcp_path is None:
        print("no .mcp.json found; there is no recorded scope to watch", file=sys.stderr)
        return EXIT_ERROR

    log_path = audit_path(config)
    interval = max(0.1, args.interval)
    width = max(
        60, min(shutil.get_terminal_size((watch_mod.DEFAULT_WIDTH, 24)).columns, 120)
    )
    interactive = sys.stdout.isatty()
    color = not args.no_color and interactive and os.environ.get("NO_COLOR") is None

    started = time.time()
    state = watch_mod.snapshot(mcp_path)
    alerts: list[watch_mod.Alert] = []

    def frame() -> str:
        launches, note = _read_launches(log_path, args.limit)
        return watch_mod.render(
            state,
            launches,
            alerts,
            started=started,
            now_ts=time.time(),
            width=width,
            color=color,
            log_note=note,
        )

    if args.once:
        print(frame().rstrip("\n"))
        return EXIT_OK

    alarms = 0
    try:
        while True:
            if interactive:
                sys.stdout.write("\x1b[H\x1b[J")
            sys.stdout.write(frame())
            sys.stdout.flush()
            time.sleep(interval)
            sampled = watch_mod.snapshot(mcp_path)
            change = watch_mod.compare(state, sampled)
            if change is not None:
                alerts.append(change)
                if change.level == watch_mod.ALARM:
                    alarms += 1
            state = sampled
    except KeyboardInterrupt:
        print()
        print(f"{PROG}: watch stopped after {int(time.time() - started)}s with {alarms} alarm(s)", file=sys.stderr)
        return EXIT_ERROR if alarms else EXIT_OK


# ------------------------------------------------------------------ doctor


def cmd_doctor(config: config_mod.Config, problems: list[str]) -> int:
    ok = True

    kimi = resolve_kimi_bin(config)
    kimi_found = bool(shutil.which(kimi)) or Path(kimi).is_file()
    print(f"kimi binary        : {kimi} {'ok' if kimi_found else 'MISSING'}")
    ok &= kimi_found

    if config.source:
        config_state = "ok"
    elif problems:
        config_state = "unreadable (using defaults)"
    else:
        config_state = "absent (defaults)"
    print(f"config file        : {config_mod.config_path()} {config_state}")

    try:
        mcp_path = mcpscope.find()
    except mcpscope.McpNotFound:
        print("mcp.json           : none in this directory tree")
    else:
        print(f"mcp.json           : {mcp_path}")
        try:
            print(f"recorded scope     : {mcpscope.read_scope(mcp_path) or 'none'}")
        except mcpscope.McpError as exc:
            print(f"recorded scope     : unreadable ({exc})")
            ok = False

    installed = theme_mod.is_installed()
    print(f"theme installed    : {'yes' if installed else 'no'} ({theme_mod.kimi_themes_dir()})")

    if not config.audit:
        print("audit log          : disabled")
    else:
        log_path = audit_path(config)
        try:
            entries, skipped = audit_mod.read(log_path, limit=1)
        except audit_mod.LogError as exc:
            print(f"audit log          : unreadable ({exc})")
        else:
            note = f"; {skipped} unreadable line(s) skipped" if skipped else ""
            if not entries:
                print(f"audit log          : {log_path} (nothing recorded yet)")
            else:
                print(f"audit log          : {log_path} (last launch {entries[-1].get('at', '?')}{note})")

    osint_python = config.osint.resolved_python()
    osint_script = config.osint.resolved_script()
    osint_ok = Path(osint_python).is_file() and Path(osint_script).is_file()
    print(f"osint server      : {'available' if osint_ok else 'not installed (optional)'} "
          f"({osint_script})")

    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    return EXIT_OK if ok else EXIT_ERROR


# ------------------------------------------------------------------ theme


def cmd_theme(args) -> int:
    if args.action == "install":
        edited = theme_mod.is_modified()
        already = theme_mod.is_installed()
        try:
            target = theme_mod.install(force=args.force)
        except (OSError, ValueError, FileNotFoundError) as exc:
            print(f"{PROG}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if edited and not args.force:
            print(f"{PROG}: {target} already exists and differs from the bundled theme", file=sys.stderr)
            print("re-run with --force to overwrite it", file=sys.stderr)
            return EXIT_ERROR
        if already and not args.force:
            print(f"{PROG}: theme already installed at {target} (unchanged)")
            print(f'{PROG}: set theme = "{theme_mod.THEME_NAME}" in your tui.toml to use it')
            return EXIT_OK
        print(f"{PROG}: theme written to {target}")
        print(f'{PROG}: set theme = "{theme_mod.THEME_NAME}" in your tui.toml to use it')
        return EXIT_OK

    installed = theme_mod.is_installed()
    state = "installed" if installed else "not installed"
    print(f"{theme_mod.THEME_NAME}: {state} ({theme_mod.kimi_themes_dir()})")
    return EXIT_OK


# ------------------------------------------------------------------ config


def cmd_config(args, config: config_mod.Config, problems: list[str]) -> int:
    action = args.config_command or "show"

    if action == "path":
        print(config_mod.config_path())
        return EXIT_OK

    if action == "init":
        target = config_mod.config_path()
        if target.exists():
            print(f"{PROG}: {target} already exists; leaving it alone", file=sys.stderr)
            return EXIT_ERROR
        try:
            config_mod.save(config, target)
        except OSError as exc:
            print(f"{PROG}: could not write {target}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{PROG}: wrote {target}")
        return EXIT_OK

    print(f"kimi_bin        = {config.kimi_bin}")
    print(f"default_scope   = {config.default_scope}")
    print(f"backup_keep     = {config.backup_keep}")
    print(f"write_mcp_json  = {str(config.write_mcp_json).lower()}")
    resolved_log = audit_path(config)
    print(f"audit           = {str(config.audit).lower()}")
    print(f"audit_path      = {resolved_log}{'' if config.audit_path else ' (default)'}")
    print(f"osint python    = {config.osint.python_bin}")
    print(f"osint script    = {config.osint.script}")
    print(f"osint timeout   = {config.osint.timeout_each:g}")
    lab_user = config.lab_ssh.resolved().get("LAB_SSH_USER", "")
    lab_state = lab_user or "(unset — deploy/test/persist will refuse)"
    print(f"lab_ssh user    = {lab_state}")
    print(f"config file     = {config.source or config_mod.config_path()}")
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)
    return EXIT_OK


# ------------------------------------------------------------------ agent


def cmd_agent(args, config: config_mod.Config) -> int:
    if args.list:
        configs = agent_mod.builtin_configs()
        if not configs:
            print("no built-in agent configs")
            return EXIT_OK
        for path in configs:
            try:
                ac = agent_mod.load_config(path)
                print(f"{ac.version}-{ac.name}  {path}")
            except ValueError as exc:
                print(f"{PROG}: {path}: {exc}", file=sys.stderr)
        return EXIT_OK

    if not args.config:
        print("--config is required (or use --list)", file=sys.stderr)
        return EXIT_USAGE
    if not args.target:
        print("--target is required", file=sys.stderr)
        return EXIT_USAGE
    if ":" not in args.target:
        print(f"--target must be HOST:PORT, got {args.target!r}", file=sys.stderr)
        return EXIT_USAGE

    config_path = args.config.expanduser()
    if not config_path.is_file():
        print(f"config not found: {config_path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        mcp_path = resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if mcp_path is None:
        print("no .mcp.json here or in any parent directory; nothing to scope", file=sys.stderr)
        print("record a scope with `evilkit scope set ...` before running the agent", file=sys.stderr)
        return EXIT_ERROR

    try:
        recorded = mcpscope.read_scope(mcp_path)
    except mcpscope.McpError as exc:
        print(f"cannot read the recorded scope from {mcp_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not recorded:
        print(f"{mcp_path} records no scope; set one before running the agent", file=sys.stderr)
        return EXIT_ERROR

    if not scope_mod.target_in_scope(args.target, recorded):
        print(f"--target {args.target!r} is not within the recorded scope ({recorded})", file=sys.stderr)
        print("widen the scope deliberately with `evilkit scope`, or pick an in-scope target", file=sys.stderr)
        return EXIT_ERROR

    kimi_env = launch_env(config, recorded)
    record_launch(
        config,
        recorded,
        enforced=True,
        mcp_path=mcp_path,
        kimi=resolve_kimi_bin(config),
        no_audit=getattr(args, "no_audit", False),
    )
    print(f"{PROG}: authorized scope -> {recorded}")

    try:
        return agent_mod.run(
            config_path,
            args.target,
            interactive=args.interactive,
            config=config,
            env=kimi_env,
        )
    except ValueError as exc:
        print(f"invalid agent config: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR


# ------------------------------------------------------------------ osint


def cmd_osint(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    def _event(message: str) -> None:
        print(f"{PROG}: osint {message}")

    try:
        findings = osint_mod.run_stage(
            split_seeds(args.seeds),
            python_bin=config.osint.resolved_python(),
            script=config.osint.resolved_script(),
            timeout_each=config.osint.timeout_each,
            only=split_tools(args.only),
            skip=split_tools(args.skip),
            on_event=_event,
        )
    except osint_mod.McpConnectionError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        print("check `evilkit doctor` and the [osint] table in your config", file=sys.stderr)
        return EXIT_ERROR

    target = args.json_path if args.json_path is not None else Path.cwd() / "osint-findings.json"
    try:
        written = osint_mod.write_findings(findings, target)
    except OSError as exc:
        print(f"{PROG}: could not write {target}: {exc}", file=sys.stderr)
        written = None

    rows = osint_mod.candidate_table(findings)
    display = rows[:OSINT_DISPLAY_LIMIT]
    print()
    print("OSINT findings (passive public sources only; nothing was probed):")
    for number, value, kind, sources, eligible in display:
        suffix = "" if eligible else "   (not scope-eligible)"
        print(f"  {number:>3}  {value:<44} {kind:<9} [{sources}]{suffix}")
    if len(rows) > len(display):
        print(f"  ... {len(rows) - len(display)} more candidates in the findings file")
    eligible_count = sum(1 for row in rows if row[4])
    print()
    if len(findings.get("runs", [])) == 0 and not rows:
        print("no runs planned: check the seeds against `evilkit osint --help`", file=sys.stderr)
        return EXIT_ERROR
    print(f"{len(rows)} candidates ({eligible_count} scope-eligible)")
    if written is None:
        return EXIT_ERROR

    if args.attach:
        mcp_path = resolve_mcp_path(None)
        if mcp_path is None:
            print("no .mcp.json here or in any parent directory; nothing to attach to", file=sys.stderr)
            return EXIT_ERROR
        try:
            changed = mcpscope.ensure_osint_server(
                mcp_path,
                [config.osint.resolved_python(), config.osint.resolved_script()],
                keep_backups=config.backup_keep,
            )
        except mcpscope.McpError as exc:
            print(f"{PROG}: could not attach the osint MCP server ({exc})", file=sys.stderr)
            return EXIT_ERROR
        state = "attached in" if changed else "already attached to"
        print(f"{PROG}: osint MCP server {state} {mcp_path}")

    print(f"{PROG}: findings -> {written}")
    return EXIT_OK


# ------------------------------------------------------------------ lessons / learning


def cmd_lessons(args) -> int:
    from . import lessons

    action = args.lessons_command or "show"
    if action == "path":
        print(lessons.lessons_path())
        return EXIT_OK
    if action == "show":
        body = lessons.load_lessons()
        print(body, end="" if body.endswith("\n") else "\n")
        return EXIT_OK
    if action == "add":
        try:
            number = lessons.append_lesson(args.title, args.body, source=args.source)
        except ValueError as exc:
            print(f"{PROG}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"{PROG}: appended lesson L{number} to {lessons.lessons_path()}")
        return EXIT_OK
    return EXIT_USAGE


def cmd_learn(args) -> int:
    from . import learning

    action = args.learn_command or "status"
    if action == "status":
        rows = learning.generation_summary()
        if not rows:
            print("no completed sessions recorded yet")
            return EXIT_OK
        print("lessons generation  runs  actions  failure-rate")
        for row in rows:
            print(
                f"{row['fingerprint']:<19} {row['runs']:>4} {row['actions']:>8} "
                f"{row['failure_rate'] * 100:>11.1f}%"
            )
        return EXIT_OK
    if action == "rollback":
        batch, numbers = learning.rollback_last_batch()
        if not batch:
            print("no automatic lesson batch to roll back")
        else:
            print(f"rolled back batch {batch}: {', '.join('L' + str(n) for n in numbers) or 'no lessons'}")
        return EXIT_OK
    if action == "ingest":
        try:
            rows = [json.loads(line) for line in args.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, ValueError) as exc:
            print(f"{PROG}: could not read session records: {exc}", file=sys.stderr)
            return EXIT_ERROR
        report = learning.learn_from_records(rows, args.run_id or args.path.stem, apply=not args.dry_run)
        print(learning.format_report(report))
        return EXIT_OK
    return EXIT_USAGE


# ------------------------------------------------------------------ hooks / dashboard


def cmd_calls(args) -> int:
    """Classify the calls in a session log, or audit a run's three records."""
    path = Path(args.path).expanduser()
    if getattr(args, "calls_command", None) == "verify-run":
        from . import run_audit

        if not path.is_dir():
            print(f"{PROG}: no such run directory: {path}", file=sys.stderr)
            return EXIT_ERROR
        report = run_audit.verify_run(path, session_dir=args.session_dir)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(run_audit.format_audit(report))
        return EXIT_OK if report["ok"] else EXIT_ERROR

    if not path.is_file():
        print(f"{PROG}: no such log: {path}", file=sys.stderr)
        return EXIT_ERROR
    report = taxonomy_mod.taxonomy(path)
    if args.json:
        print(json.dumps(report, indent=2))
        return EXIT_OK
    print(taxonomy_mod.format_taxonomy(report, limit=args.limit))
    return EXIT_OK


def cmd_hooks(args) -> int:
    from . import kimihook, qwenhooks

    engines = ("kimi", "qwen") if args.engine == "all" else (args.engine,)
    failures = 0
    for engine in engines:
        if engine == "kimi":
            path = Path.home() / ".kimi-code" / "config.toml"
            if args.hooks_action == "status":
                print(f"kimi: {'installed' if kimihook.hooks_installed(path) else 'not installed'} ({path})")
                continue
            changed, message = kimihook.install_hooks(path)
        else:
            path = qwenhooks.settings_path()
            if args.hooks_action == "status":
                print(f"qwen: {'installed' if qwenhooks.hooks_installed(path) else 'not installed'} ({path})")
                continue
            changed, message = qwenhooks.install_hooks(path)
        print(f"{engine}: {message}")
        if not changed and "already" not in message:
            failures += 1
    return EXIT_ERROR if failures else EXIT_OK


def cmd_dashboard(args) -> int:
    run_dir = args.run_dir.expanduser()
    if args.dashboard_action == "status":
        path = run_dir / "dashboard" / "status.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"{PROG}: could not read {path}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(json.dumps(value, indent=2))
        return EXIT_OK

    path = run_dir / "journal.jsonl"
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        print(f"{PROG}: could not read {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for line in lines[-args.limit:] if args.limit else lines:
        print(line)
    return EXIT_OK


def cmd_patch_diff_poc(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    try:
        commit = pdp_mod.parse_commit_url(args.commit)
    except pdp_mod.PatchDiffError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    token = pdp_mod.github_token()
    try:
        meta = pdp_mod.fetch_commit(commit, token=token, timeout=args.timeout)
        diff = pdp_mod.fetch_diff(commit, token=token, timeout=args.timeout)
    except pdp_mod.PatchDiffError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        if not token:
            print(f"{PROG}: tip: set GITHUB_TOKEN for higher API rate limits", file=sys.stderr)
        return EXIT_ERROR

    recipe = pdp_mod.build_recipe(commit, meta, diff)

    if args.print_only:
        json.dump(recipe.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_OK

    out_dir = args.out_dir or Path.cwd()
    try:
        script = pdp_mod.render_script(recipe, flag_path=args.flag_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"poc_{commit.owner}_{commit.repo}_{commit.sha[:12]}"
        recipe_path = out_dir / f"{stem}.recipe.json"
        script_path = out_dir / f"{stem}.py"
        recipe_path.write_text(json.dumps(recipe.to_dict(), indent=2), encoding="utf-8")
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o755)
    except OSError as exc:
        print(f"{PROG}: could not write PoC files: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"{PROG}: patch-diff-poc  {commit.slug}")
    print(f"  sink class     : {recipe.sink_class}")
    print(f"  cve            : {recipe.cve_id or '(unlabelled)'}")
    print(f"  files touched  : {len(recipe.affected_files)}")
    if recipe.params:
        print(f"  params found   : {', '.join(recipe.params)}")
    if recipe.endpoint_hints:
        print(f"  endpoints      : {', '.join(recipe.endpoint_hints)}")
    print(f"  recipe written : {recipe_path}")
    print(f"  script written : {script_path}")
    print()
    print("Next: run the script with --target <base-url> --scope-file <allow-list>.")
    print("The script refuses to fire if the target host is not in the scope file.")
    return EXIT_OK


def cmd_script_harness(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    scope = args.scope or config.default_scope
    try:
        record = script_harness_mod.run(
            args.script,
            target=args.target,
            scope=scope,
            sandbox=args.sandbox,
            timeout=args.timeout,
            evidence_dir=args.evidence_dir,
            passthrough=args.args,
            pcap_iface=args.pcap_iface,
        )
    except script_harness_mod.ScriptHarnessError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    evidence_dir = args.evidence_dir or Path.cwd()
    out_path = evidence_dir / f"harness-{int(record['timestamp'])}.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print(f"{PROG}: script-harness  {record['script']}")
    print(f"  target    : {record['target']}")
    print(f"  sandbox   : {record['sandbox']}")
    print(f"  exit      : {record['returncode']}")
    print(f"  duration  : {record['duration_s']}s")
    diff = record["fs_diff"]
    print(f"  fs diff   : +{len(diff['added'])} ~{len(diff['changed'])} -{len(diff['removed'])}")
    if record["pcap"]:
        print(f"  pcap      : {record['pcap']}")
    print(f"  evidence  : {out_path}")
    return EXIT_OK


def cmd_appliance(args, config: config_mod.Config, problems: list[str]) -> int:
    if getattr(args, "appliance_command", "seed") == "build":
        return cmd_appliance_build(args, config, problems)

    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    spec = appliance_mod.ApplianceSpec(
        hostname=args.hostname,
        admin_user=args.user,
        ssh_keys=list(args.ssh_key),
        scope=args.scope,
        mesh_leader=args.mesh_leader,
        mesh_token=args.mesh_token,
        install_source=args.install_source,
        timezone=args.timezone,
    )
    invalid = spec.validate()
    if invalid:
        for problem in invalid:
            print(f"{PROG}: {problem}", file=sys.stderr)
        return EXIT_USAGE

    try:
        written = appliance_mod.write_seed(spec, args.out_dir)
    except OSError as exc:
        print(f"{PROG}: could not write appliance seed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"{PROG}: appliance seed -> {args.out_dir}")
    for name, path in written.items():
        print(f"  {name:20} {path}")
    print()
    print("Burn the seed into a NoCloud datasource (cidata), or copy bootstrap.sh")
    print("onto a raw image's first-boot hook. First boot installs the operator")
    print(f"system, records scope '{args.scope}', and writes its manifest.")
    return EXIT_OK


def cmd_appliance_build(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        print(f"{PROG}: {problem}", file=sys.stderr)

    spec = build_mod.PiBuildSpec(
        hostname=args.hostname,
        admin_user=args.user,
        ssh_keys=list(args.ssh_key),
        scope=args.scope,
        mesh_leader=args.mesh_leader,
        mesh_token=args.mesh_token,
        eth0_ip=args.eth0,
        gateway=args.gateway,
        dns=args.dns,
        wifi_ssid=args.wifi_ssid,
        wifi_psk=args.wifi_psk,
        wifi_country=args.wifi_country,
        wheel=args.wheel,
        base_image=args.base_image,
        output=args.output,
        boot_offset=args.boot_offset,
    )
    invalid = spec.validate()
    if invalid:
        for problem in invalid:
            print(f"{PROG}: {problem}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = build_mod.build_pi_image(spec, dry_run=args.dry_run)
    except build_mod.BuildError as exc:
        print(f"{PROG}: build failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if result.dry_run:
        bake_dir = args.output.parent / (args.output.name + ".bake")
        print(f"{PROG}: dry run — no image written; artifacts in {bake_dir}")
        for cmd in result.plan:
            print("  " + " ".join(shlex.quote(a) for a in cmd))
        return EXIT_OK

    print(f"{PROG}: baked {result.output}")
    print(f"{PROG}: manifest -> {result.output}.manifest.md")
    return EXIT_OK

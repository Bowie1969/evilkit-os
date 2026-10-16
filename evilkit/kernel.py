"""Shared launch and session primitives used by the EvilKit CLI commands.

This module is the thin core that sits between argparse and the domain modules.
It knows how to resolve a target ``.mcp.json``, collect and normalise a scope,
record it atomically, append the launch log, and build the environment handed to
the Kimi Code CLI. Some functions print status or warnings directly, since the
CLI is the only consumer; command-specific logic lives in ``commands.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import audit as audit_mod
from . import config as config_mod
from . import mcpscope
from . import scope as scope_mod

__all__ = [
    "PROG",
    "IDENTITY",
    "EXIT_OK",
    "EXIT_ERROR",
    "EXIT_USAGE",
    "resolve_mcp_path",
    "collect_scope",
    "normalise_deny",
    "deny_note",
    "apply_scope",
    "audit_path",
    "record_launch",
    "launch_env",
    "split_tools",
    "split_seeds",
    "resolve_kimi_bin",
]

PROG = "evilkit"
IDENTITY = "evilkit"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def resolve_mcp_path(explicit: Path | None) -> Path | None:
    """Locate ``.mcp.json``: explicit path, nearest one, or None."""
    if explicit is not None:
        resolved = explicit.expanduser()
        if not resolved.is_file():
            raise mcpscope.McpNotFound(f"{resolved} does not exist")
        return resolved.resolve()
    try:
        return mcpscope.find()
    except mcpscope.McpNotFound:
        return None


def _prompt_scope(config: config_mod.Config) -> str:
    """Ask for a scope. Returns the raw answer, which may be empty."""
    default = config.default_scope
    hint = f" [enter = {default}]"
    try:
        answer = input(f"scope{hint}> ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return answer


def collect_scope(args, config: config_mod.Config) -> str:
    """Work out the scope to use, from the flag, the prompt, or the default."""
    if args.scope is not None:
        return args.scope.strip()

    env_value = os.environ.get(mcpscope.SCOPE_ENV_KEY, "").strip()
    if env_value:
        return env_value

    if args.yes or not sys.stdin.isatty():
        return config.default_scope

    return _prompt_scope(config).strip() or config.default_scope


def normalise_deny(raw: str | None, *, allow_any: bool) -> str | None:
    """Normalise a ``--deny`` value, or None when the flag was not given.

    None means "say nothing about the deny list". An empty string is the
    explicit "deny nothing" and is handled here rather than by ``parse_scope``,
    whose empty-string answer is the solo loopback sentinel.
    """
    if raw is None:
        return None
    if not raw.strip():
        return ""
    return scope_mod.normalise_scope(raw, allow_any=allow_any)


def deny_note(deny: str | None) -> str:
    """A suffix naming the deny list that goes with a reported scope, if any."""
    if deny is None:
        return ""
    return f" [deny: {deny or 'none'}]"


def _not_recorded(
    normalised: str, message: str, allow_unscoped: bool, dry_run: bool
) -> tuple[str, int, bool]:
    """Decide what to do when the scope could not be recorded."""
    if allow_unscoped:
        print(f"{PROG}: {message} — launching with the scope NOT recorded", file=sys.stderr)
        print(
            "the enforced scope may differ from the one requested; "
            "check .mcp.json before trusting it",
            file=sys.stderr,
        )
        if dry_run:
            print(f"{PROG}: would not record {normalised} (unscoped launch allowed)")
        return normalised, EXIT_OK, False
    print(f"{PROG}: {message}", file=sys.stderr)
    print("nothing was launched: the scope could not be recorded", file=sys.stderr)
    print("pass --allow-unscoped to launch anyway, knowing the scope may differ", file=sys.stderr)
    return "", EXIT_ERROR, False


def apply_scope(
    scope_text: str,
    mcp_path: Path | None,
    config: config_mod.Config,
    *,
    write: bool,
    allow_unscoped: bool,
    allow_any: bool,
    dry_run: bool = False,
    deny_text: str | None = None,
) -> tuple[str, int, bool]:
    """Validate the scope and record it. Returns (scope, exit_code, enforced)."""
    try:
        normalised = scope_mod.normalise_scope(scope_text, allow_any=allow_any)
    except scope_mod.ScopeError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        print("expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'", file=sys.stderr)
        return "", EXIT_USAGE, False

    try:
        deny = normalise_deny(deny_text, allow_any=allow_any)
    except scope_mod.ScopeError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        print("expected a comma-separated list of hosts, IPs or CIDRs for the deny list", file=sys.stderr)
        return "", EXIT_USAGE, False

    if not write:
        reason = "--dry-run" if dry_run else "--no-write"
        print(f"{PROG}: scope -> {normalised}{deny_note(deny)} (not written; {reason})")
        return normalised, EXIT_OK, False

    if mcp_path is None:
        return _not_recorded(
            normalised,
            "no .mcp.json here or in any parent directory; nothing to scope",
            allow_unscoped,
            dry_run,
        )

    try:
        changed = mcpscope.write_scope(
            mcp_path,
            normalised,
            keep_backups=config.backup_keep,
            dry_run=dry_run,
            deny=deny,
        )
    except mcpscope.NoPentestServer:
        return _not_recorded(
            normalised,
            f"{mcp_path} declares no 'pentest' server; nothing to scope",
            allow_unscoped,
            dry_run,
        )
    except mcpscope.McpError as exc:
        return _not_recorded(normalised, str(exc), allow_unscoped, dry_run)

    if dry_run:
        if changed:
            print(f"{PROG}: would record {normalised} in {mcp_path}{deny_note(deny)}")
        else:
            print(f"{PROG}: would leave {mcp_path} at {normalised}{deny_note(deny)}")
    elif changed:
        print(f"{PROG}: scope {normalised} recorded in {mcp_path}{deny_note(deny)}")
    else:
        print(f"{PROG}: scope already {normalised} in {mcp_path}{deny_note(deny)}")
    return normalised, EXIT_OK, True


def audit_path(config: config_mod.Config) -> Path:
    """Where the launch log lives: the configured path, else the state default."""
    if config.audit_path:
        return Path(config.audit_path).expanduser()
    return audit_mod.default_log_path()


def record_launch(
    config: config_mod.Config,
    scope: str,
    *,
    enforced: bool,
    mcp_path: Path | None,
    kimi: str,
    no_audit: bool,
) -> None:
    """Append this launch to the log, or warn why it could not be written.

    Never fatal. A launch is recorded only when it actually happens.
    """
    if no_audit or not config.audit:
        return

    path = audit_path(config)
    entry = audit_mod.launch_entry(scope, enforced=enforced, mcp_json=mcp_path, kimi=kimi)
    try:
        audit_mod.record(path, entry)
    except audit_mod.LogError as exc:
        print(f"{PROG}: could not record this launch: {exc}", file=sys.stderr)
        print("the launch is continuing; set audit = false to silence this", file=sys.stderr)


def launch_env(config: config_mod.Config, scope_value: str) -> dict[str, str]:
    """Build the environment handed to the Kimi Code CLI."""
    env = dict(os.environ)
    env.setdefault("KIMI_CODE_IDENTITY_NAME", IDENTITY)
    env.setdefault("KIMI_CODE_IDENTITY_SLUG", IDENTITY)
    env.update(config.extra_env)
    # Last, so a stray extra_env entry can never override the authorised scope.
    env[mcpscope.SCOPE_ENV_KEY] = scope_value
    return env


def split_tools(text: str | None) -> list[str] | None:
    """Split a comma-separated tool list, ignoring empty entries."""
    if not text:
        return None
    return [t for t in text.split(",") if t.strip()]


def split_seeds(raw: list[str]) -> list[str]:
    """One seed per piece, whether separated by whitespace or commas."""
    seeds: list[str] = []
    for seed in raw:
        seeds.extend(part.strip() for part in seed.split(",") if part.strip())
    return list(dict.fromkeys(seeds))


def resolve_kimi_bin(config: config_mod.Config) -> str:
    """Return the configured Kimi Code CLI binary path."""
    return config.resolved_kimi_bin()

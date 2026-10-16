"""User configuration for evilkit.

Config lives in ``$XDG_CONFIG_HOME/evilkit/config.toml`` (``~/.config/evilkit``
by default). Only ``tomllib`` from the standard library is used to read it; the
writer below covers the flat scalar values this config actually holds.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import BRAIN_MODEL, BRAIN_URL
from .clone_display import CloneTarget, DisplayConfig, SegmentError, parse_networks
from .jev import JevConfig
from .mcpscope import SCOPE_ENV_KEY
from .scope import SOLO_SCOPE, ScopeError, normalise_scope

__all__ = ["Config", "OsintConfig", "DashboardConfig", "BrainConfig", "LabSshConfig", "JevConfig", "DisplayConfig", "config_dir", "config_path", "load", "save"]

APP_NAME = "evilkit"

_TOML_STRING_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")


def _escape_string(text: str) -> str:
    """Escape ``text`` for a TOML basic string.

    Everything below 0x20 and 0x7f must be escaped: left raw, ``tomllib``
    refuses the file and the whole configuration reverts to defaults.
    """
    parts = []
    for char in text:
        if char in _TOML_STRING_ESCAPES:
            parts.append(_TOML_STRING_ESCAPES[char])
        elif char < " " or char == "\x7f":
            parts.append(f"\\u{ord(char):04X}")
        else:
            parts.append(char)
    return "".join(parts)


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / APP_NAME


def config_path() -> Path:
    override = os.environ.get("EVILKIT_CONFIG")
    return Path(override) if override else config_dir() / "config.toml"


@dataclass
class OsintConfig:
    """:mod:`evilkit.osint` stage settings. Values may start with ``~``.

    The defaults point at the standalone passive OSINT MCP server; the stage
    is optional and a missing server must degrade to a clear error, never a
    launch.
    """

    python_bin: str = "~/tools/osint-mcp/venv/bin/python"
    script: str = "~/tools/osint-mcp/server.py"
    timeout_each: float = 240.0

    def resolved_python(self) -> str:
        return os.path.expanduser(self.python_bin)

    def resolved_script(self) -> str:
        return os.path.expanduser(self.script)


@dataclass
class DashboardConfig:
    """The lab dashboard's run controls, exposed to the session as MCP tools.

    ``url`` is the dashboard's base URL (empty means the tools are not attached:
    there is no default address, because a guessed host would either fail
    obscurely or reach something that is not this board). ``attach`` decides
    whether a launch declares the ``dashboard`` MCP server in the file the
    engine actually reads. ``auto`` additionally drives the board from the
    launcher: it starts tracking this launch's run before the session and stops
    tracking when the session ends — but only if that launch is what started it,
    so a run someone else put on the board is never taken off by this exit.

    The controls are the board's own fixed scripts, and those are bookkeeping
    (``keystone/run_control.py``): they update a prepared run's dashboard status.
    They do not launch or tear down the range, and they do not start or stop an
    operator session. They are, however, unauthenticated on the board's network:
    the endpoints carry a same-origin check rather than auth, so reaching ``url``
    is the whole authority.
    """

    url: str = ""
    attach: bool = False
    auto: bool = False
    timeout: float = 5.0

    def resolved_url(self) -> str:
        """The URL to use, with an exported ``EVILKIT_DASHBOARD_URL`` winning."""
        return os.environ.get("EVILKIT_DASHBOARD_URL", "").strip() or self.url.strip()

    def enabled(self) -> bool:
        return bool(self.resolved_url())


@dataclass
class LabSshConfig:
    """Guest credentials for the malware-scripting MCP's ssh-backed tools.

    ``malware_deploy`` / ``malware_test`` / ``malware_persist`` refuse to run
    without these: they will not fabricate a deploy, and they will not run a
    command on the MCP host and label it remote. So the launch environment is
    where they have to arrive from — they are exported into the session, which
    the MCP child inherits, and never written into ``.mcp.json`` or a repository.
    An already-set ``LAB_SSH_*`` variable always wins over the config file.
    """

    user: str = ""
    password: str = ""
    key: str = ""

    def resolved(self) -> dict[str, str]:
        """The ``LAB_SSH_*`` environment the MCP server reads."""
        out: dict[str, str] = {}
        user = os.environ.get("LAB_SSH_USER") or self.user
        password = os.environ.get("LAB_SSH_PASS") or self.password
        key = os.environ.get("LAB_SSH_KEY") or self.key
        if user:
            out["LAB_SSH_USER"] = user
        if password:
            out["LAB_SSH_PASS"] = password
        if key:
            out["LAB_SSH_KEY"] = os.path.expanduser(key)
        return out

    def missing(self) -> list[str]:
        """What still has to be supplied for the ssh-backed tools to run."""
        resolved = self.resolved()
        if "LAB_SSH_USER" not in resolved:
            return ["LAB_SSH_USER", "LAB_SSH_PASS or LAB_SSH_KEY"]
        if "LAB_SSH_PASS" not in resolved and "LAB_SSH_KEY" not in resolved:
            return ["LAB_SSH_PASS or LAB_SSH_KEY"]
        return []


@dataclass
class BrainConfig:
    """Hosted operator/auditor settings retained for compatible brain profiles."""

    operator_url: str = BRAIN_URL
    operator_model: str = BRAIN_MODEL
    operator_key: str = ""
    auditor_url: str = BRAIN_URL
    auditor_model: str = "venice-uncensored-1-1"
    auditor_key: str = ""
    brain_max_turns: int = 50
    brain_executor: str = "simulation"
    operator_subscription_first: bool = True

    def resolved_operator_url(self) -> str:
        return os.environ.get("EVILKIT_OPERATOR_URL", self.operator_url)

    def resolved_operator_model(self) -> str:
        return os.environ.get("EVILKIT_OPERATOR_MODEL", self.operator_model)

    def resolved_operator_key(self) -> str:
        return os.environ.get("EVILKIT_OPERATOR_KEY", self.operator_key)

    def resolved_auditor_url(self) -> str:
        return os.environ.get("EVILKIT_AUDITOR_URL", self.auditor_url)

    def resolved_auditor_model(self) -> str:
        return os.environ.get("EVILKIT_AUDITOR_MODEL", self.auditor_model)

    def resolved_auditor_key(self) -> str:
        return os.environ.get("EVILKIT_AUDITOR_KEY", self.auditor_key)

    def resolved_brain_max_turns(self) -> int:
        try:
            return int(os.environ.get("EVILKIT_BRAIN_MAX_TURNS", self.brain_max_turns))
        except ValueError:
            return self.brain_max_turns

    def resolved_brain_executor(self) -> str:
        return os.environ.get("EVILKIT_BRAIN_EXECUTOR", self.brain_executor)


@dataclass
class Config:
    """Resolved settings, with every field defaulted to something safe."""

    kimi_bin: str = "kimi"
    default_scope: str = SOLO_SCOPE
    backup_keep: int = 5
    write_mcp_json: bool = True
    audit: bool = True
    audit_path: str = ""
    extra_env: dict[str, str] = field(default_factory=dict)
    osint: OsintConfig = field(default_factory=OsintConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    brain: BrainConfig = field(default_factory=BrainConfig)
    jev: JevConfig = field(default_factory=JevConfig)
    clone_display: DisplayConfig = field(default_factory=DisplayConfig)
    lab_ssh: LabSshConfig = field(default_factory=LabSshConfig)

    #: Populated by :func:`load` so callers can report where settings came from.
    source: Path | None = None

    def resolved_kimi_bin(self) -> str:
        """Return an executable path for the Kimi Code CLI.

        Order: an explicit env override, then the configured value, then a
        lookup on PATH. A configured value wins over PATH so a pinned version
        is honoured, but a bare name is still resolved through PATH.
        """
        import shutil

        override = os.environ.get("EVILKIT_KIMI_BIN")
        if override:
            return override
        if os.sep in self.kimi_bin:
            return os.path.expanduser(self.kimi_bin)
        found = shutil.which(self.kimi_bin)
        return found or self.kimi_bin


def _coerce_osint(raw: dict, problems: list[str]) -> dict:
    """Validate the ``[osint]`` table into raw values for OsintConfig."""
    values: dict = {}
    known = {"python", "script", "timeout_each"}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [osint] key {key!r} ignored")
    if "python" in raw:
        if isinstance(raw["python"], str) and raw["python"].strip():
            values["python_bin"] = raw["python"].strip()
        else:
            problems.append("[osint] python must be a non-empty string")
    if "script" in raw:
        if isinstance(raw["script"], str) and raw["script"].strip():
            values["script"] = raw["script"].strip()
        else:
            problems.append("[osint] script must be a non-empty string")
    if "timeout_each" in raw:
        value = raw["timeout_each"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            problems.append("[osint] timeout_each must be a positive number")
        else:
            values["timeout_each"] = float(value)
    return values


def _coerce_dashboard(raw: dict, problems: list[str]) -> DashboardConfig:
    """Validate the ``[dashboard]`` table into a DashboardConfig.

    The URL is the whole authority for the run controls (the dashboard's own
    endpoints are unauthenticated on its network), so a value that is not an
    http(s) URL is reported and dropped rather than passed on to be fetched.
    """
    known = {"url", "attach", "auto", "timeout"}
    values: dict = {}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [dashboard] key {key!r} ignored")
    if "url" in raw:
        if isinstance(raw["url"], str):
            values["url"] = raw["url"].strip().rstrip("/")
        else:
            problems.append("[dashboard] url must be a string")
    for key in ("attach", "auto"):
        if key in raw:
            if isinstance(raw[key], bool):
                values[key] = raw[key]
            else:
                problems.append(f"[dashboard] {key} must be true or false")
    if "timeout" in raw:
        value = raw["timeout"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            problems.append("[dashboard] timeout must be a positive number")
        else:
            values["timeout"] = float(value)
    url = values.get("url", "")
    if url and not url.startswith(("http://", "https://")):
        problems.append(f"[dashboard] url must be an http:// or https:// URL (got {url!r}); ignored")
        values.pop("url", None)
    if values.get("attach") and not values.get("url"):
        problems.append(
            "[dashboard] attach is true but url is empty; set url (or export "
            "EVILKIT_DASHBOARD_URL) or nothing will be attached"
        )
    if values.get("auto") and not values.get("url"):
        problems.append(
            "[dashboard] auto is true but url is empty; set url (or export "
            "EVILKIT_DASHBOARD_URL) or the range will not be driven"
        )
    return DashboardConfig(**values)


def _coerce_brain(raw: dict, problems: list[str]) -> BrainConfig:
    known = {
        "operator_url", "operator_model", "operator_key", "auditor_url",
        "auditor_model", "auditor_key", "brain_max_turns", "brain_executor",
        "operator_subscription_first",
    }
    values: dict = {}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [brain] key {key!r} ignored")
    for key in ("operator_url", "operator_model", "operator_key", "auditor_url", "auditor_model", "auditor_key"):
        if key in raw:
            if isinstance(raw[key], str):
                values[key] = raw[key]
            else:
                problems.append(f"[brain] {key} must be a string")
    if "brain_max_turns" in raw:
        value = raw["brain_max_turns"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            problems.append("[brain] brain_max_turns must be a positive integer")
        else:
            values["brain_max_turns"] = value
    if "brain_executor" in raw:
        value = raw["brain_executor"]
        if value in {"simulation", "shell"}:
            values["brain_executor"] = value
        else:
            problems.append("[brain] brain_executor must be 'simulation' or 'shell'")
    if "operator_subscription_first" in raw:
        value = raw["operator_subscription_first"]
        if isinstance(value, bool):
            values["operator_subscription_first"] = value
        else:
            problems.append("[brain] operator_subscription_first must be true or false")
    return BrainConfig(**values)


def _coerce_jev(raw: dict, problems: list[str]) -> JevConfig:
    known = {"enabled", "endpoint", "model", "api_key", "timeout", "loop_threshold"}
    values: dict = {}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [jev] key {key!r} ignored")
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            values["enabled"] = raw["enabled"]
        else:
            problems.append("[jev] enabled must be true or false")
    for key in ("endpoint", "model", "api_key"):
        if key in raw:
            if isinstance(raw[key], str):
                values[key] = raw[key]
            else:
                problems.append(f"[jev] {key} must be a string")
    for key in ("timeout", "loop_threshold"):
        if key in raw:
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                problems.append(f"[jev] {key} must be a number")
            elif key == "timeout" and value <= 0:
                problems.append("[jev] timeout must be greater than zero")
            elif key == "loop_threshold" and not 0 <= value <= 1:
                problems.append("[jev] loop_threshold must be between zero and one")
            else:
                values[key] = float(value)
    return JevConfig(**values)


def _coerce_clone_display(raw: dict, problems: list[str]) -> DisplayConfig:
    """Validate the ``[clone_display]`` table.

    The attack segment is the whole security boundary for this feature, so a
    bad value is reported and dropped rather than guessed at.
    """
    known = {"enabled", "segments", "deny", "targets", "poll_interval", "terminal", "log",
             "name", "host", "user", "identity", "unit"}
    values: dict = {}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [clone_display] key {key!r} ignored")

    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            values["enabled"] = raw["enabled"]
        else:
            problems.append("[clone_display] enabled must be true or false")

    for key in ("segments", "deny"):
        if key in raw:
            entries = raw[key]
            if not isinstance(entries, list) or not all(isinstance(v, str) for v in entries):
                problems.append(f"[clone_display] {key} must be an array of CIDR strings")
                continue
            try:
                parse_networks(entries)
            except SegmentError as exc:
                problems.append(f"[clone_display] {key} rejected ({exc})")
                continue
            values[key] = tuple(v.strip() for v in entries if v.strip())

    for key in ("terminal", "log"):
        if key in raw:
            if isinstance(raw[key], str):
                values[key] = raw[key].strip()
            else:
                problems.append(f"[clone_display] {key} must be a string")

    if "poll_interval" in raw:
        poll = raw["poll_interval"]
        if isinstance(poll, bool) or not isinstance(poll, (int, float)) or poll <= 0:
            problems.append("[clone_display] poll_interval must be a positive number")
        else:
            values["poll_interval"] = float(poll)
    if "targets" in raw:
        entries = raw["targets"]
        if not isinstance(entries, list):
            problems.append("[clone_display] targets must be an array of tables ([[clone_display.targets]])")
        else:
            targets: list[CloneTarget] = []
            for index, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    problems.append(f"[clone_display] targets[{index}] must be a table")
                    continue
                name = str(entry.get("name", "")).strip()
                host = str(entry.get("host", "")).strip()
                if not name or not host:
                    problems.append(
                        f"[clone_display] targets[{index}] needs both name and host"
                    )
                    continue
                targets.append(
                    CloneTarget(
                        name=name,
                        host=host,
                        user=str(entry.get("user", "pi")).strip() or "pi",
                        identity=str(entry.get("identity", "~/.ssh/id_ed25519_evilkimi_pi")).strip(),
                        unit=str(entry.get("unit", "evilk-mesh-worker-pi.service")).strip(),
                    )
                )
            values["targets"] = tuple(targets)

    # Defaults (or an explicit entry) must survive the guard: a target that cannot
    # be shown on any attack segment is dropped here, not at display time.
    segments = values.get("segments", DisplayConfig().segments)
    deny = values.get("deny", DisplayConfig().deny)
    keepeable: list[CloneTarget] = []
    for target in values.get("targets", DisplayConfig().targets):
        from .clone_display import attack_segment_of

        try:
            attack_segment_of(target.host, segments, deny)
        except SegmentError as exc:
            problems.append(f"[clone_display] target {target.name!r} rejected ({exc})")
            continue
        keepeable.append(target)
    if "targets" in values:
        values["targets"] = tuple(keepeable)

    return DisplayConfig(**values)


def _coerce_lab_ssh(raw: dict, problems: list[str]) -> LabSshConfig:
    """Validate the ``[lab_ssh]`` table into a LabSshConfig.

    Only the two shapes a guest login can take are accepted: a password, or a
    private key path. Both together are allowed (a key with a passphrase-less
    login plus a password fallback), neither is reported as a problem because a
    passwordless key is legitimate.
    """
    values: dict = {}
    known = {"user", "password", "key"}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [lab_ssh] key {key!r} ignored")
    for key in ("user", "password", "key"):
        if key in raw:
            if isinstance(raw[key], str):
                values[key] = raw[key].strip()
            else:
                problems.append(f"[lab_ssh] {key} must be a string")
    if values.get("key"):
        values["key"] = os.path.expanduser(values["key"])
    return LabSshConfig(**values)


def _coerce(raw: dict) -> tuple[dict, list[str]]:
    known = {
        "kimi_bin",
        "default_scope",
        "backup_keep",
        "write_mcp_json",
        "audit",
        "audit_path",
        "extra_env",
        "osint",
        "dashboard",
        "brain",
        "jev",
        "clone_display",
        "lab_ssh",
    }
    values: dict = {}
    problems: list[str] = []

    for key in raw:
        if key not in known:
            problems.append(f"unknown key {key!r} ignored")

    if "kimi_bin" in raw:
        if isinstance(raw["kimi_bin"], str) and raw["kimi_bin"].strip():
            values["kimi_bin"] = raw["kimi_bin"].strip()
        else:
            problems.append("kimi_bin must be a non-empty string")

    if "default_scope" in raw:
        try:
            values["default_scope"] = normalise_scope(str(raw["default_scope"]))
        except ScopeError as exc:
            problems.append(f"default_scope rejected ({exc}); using {SOLO_SCOPE}")

    if "backup_keep" in raw:
        keep = raw["backup_keep"]
        if isinstance(keep, bool) or not isinstance(keep, int):
            problems.append("backup_keep must be an integer")
        elif keep < 0:
            problems.append("backup_keep must be zero or greater")
        else:
            values["backup_keep"] = keep

    if "write_mcp_json" in raw:
        if isinstance(raw["write_mcp_json"], bool):
            values["write_mcp_json"] = raw["write_mcp_json"]
        else:
            problems.append("write_mcp_json must be true or false")

    if "audit" in raw:
        if isinstance(raw["audit"], bool):
            values["audit"] = raw["audit"]
        else:
            problems.append("audit must be true or false")

    if "audit_path" in raw:
        if isinstance(raw["audit_path"], str):
            values["audit_path"] = raw["audit_path"].strip()
        else:
            problems.append("audit_path must be a string")

    if "extra_env" in raw:
        if isinstance(raw["extra_env"], dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw["extra_env"].items()
        ):
            extra = dict(raw["extra_env"])
            if SCOPE_ENV_KEY in extra:
                del extra[SCOPE_ENV_KEY]
                problems.append(
                    f"extra_env cannot set {SCOPE_ENV_KEY}; "
                    "the authorised scope is the one that is recorded"
                )
            values["extra_env"] = extra
        else:
            problems.append("extra_env must be a table of string values")

    if "osint" in raw:
        if isinstance(raw["osint"], dict):
            values["osint"] = OsintConfig(**_coerce_osint(raw["osint"], problems))
        else:
            problems.append("[osint] must be a table ([osint] python = ...)")

    if "dashboard" in raw:
        if isinstance(raw["dashboard"], dict):
            values["dashboard"] = _coerce_dashboard(raw["dashboard"], problems)
        else:
            problems.append("[dashboard] must be a table")

    if "brain" in raw:
        if isinstance(raw["brain"], dict):
            values["brain"] = _coerce_brain(raw["brain"], problems)
        else:
            problems.append("[brain] must be a table")

    if "jev" in raw:
        if isinstance(raw["jev"], dict):
            values["jev"] = _coerce_jev(raw["jev"], problems)
        else:
            problems.append("[jev] must be a table")

    if "clone_display" in raw:
        if isinstance(raw["clone_display"], dict):
            values["clone_display"] = _coerce_clone_display(raw["clone_display"], problems)
        else:
            problems.append("[clone_display] must be a table")

    if "lab_ssh" in raw:
        if isinstance(raw["lab_ssh"], dict):
            values["lab_ssh"] = _coerce_lab_ssh(raw["lab_ssh"], problems)
        else:
            problems.append("[lab_ssh] must be a table")

    return values, problems


def load(path: Path | None = None) -> tuple[Config, list[str]]:
    """Load config from ``path`` (default: the standard location).

    A missing file is not an error — defaults apply. A malformed file is
    reported through the returned problems list rather than raised, so a typo
    in config never stops someone launching a session.
    """
    target = path or config_path()
    if not target.exists():
        return Config(), []

    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return Config(), [f"could not read {target}: {exc}"]
    except RecursionError:
        return Config(), [f"could not read {target}: nested too deeply to parse"]

    values, problems = _coerce(raw)
    config = Config(**values)
    config.source = target
    return config, problems


def _format_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    return f'"{_escape_string(text)}"'


def _format_key(key: str) -> str:
    """Emit ``key`` bare when TOML allows it, quoted otherwise."""
    if _BARE_KEY_RE.fullmatch(key):
        return key
    return _format_value(key)


def _format_array(values) -> str:
    return "[" + ", ".join(_format_value(str(value)) for value in values) + "]"


def dumps(config: Config) -> str:
    lines = [
        "# evilkit configuration",
        "# Docs: https://github.com/Bowie1969/evilkit",
        "",
        "# Command or absolute path for the Kimi Code CLI.",
        f"kimi_bin = {_format_value(config.kimi_bin)}",
        "",
        "# Scope used when you accept the prompt without typing anything.",
        f"default_scope = {_format_value(config.default_scope)}",
        "",
        "# How many .mcp.json backups to keep beside a project (0 disables).",
        f"backup_keep = {config.backup_keep}",
        "",
        "# Set false to launch without touching .mcp.json at all.",
        f"write_mcp_json = {_format_value(config.write_mcp_json)}",
        "",
        "# Record every launch in a local append-only log.",
        f"audit = {_format_value(config.audit)}",
        "",
        "# Where that log lives (empty: $XDG_STATE_HOME/evilkit/launches.jsonl).",
        f"audit_path = {_format_value(config.audit_path)}",
    ]
    if config.extra_env:
        lines += ["", "[extra_env]"]
        lines += [
            f"{_format_key(key)} = {_format_value(val)}"
            for key, val in sorted(config.extra_env.items())
        ]
    lines += [
        "",
        "[osint]",
        "# Passive OSINT stage: the standalone osint MCP server evilkit drives.",
        f"python = {_format_value(config.osint.python_bin)}",
        f"script = {_format_value(config.osint.script)}",
        f"timeout_each = {config.osint.timeout_each:g}",
        "",
        "[dashboard]",
        "# Lab dashboard whose run controls the session may call as MCP tools",
        "# (start_run, stop_run, end_run, run_status). An empty url attaches nothing:",
        "# there is no default address, so set the board you actually mean.",
        f"url = {_format_value(config.dashboard.url)}",
        f"attach = {_format_value(config.dashboard.attach)}",
        "# auto also drives the range from the launcher: up before the session,",
        "# down again when it ends - but only if this launch brought it up.",
        f"auto = {_format_value(config.dashboard.auto)}",
        f"timeout = {config.dashboard.timeout:g}",
        "",
        "[brain]",
        f"operator_url = {_format_value(config.brain.operator_url)}",
        f"operator_model = {_format_value(config.brain.operator_model)}",
        f"auditor_url = {_format_value(config.brain.auditor_url)}",
        f"auditor_model = {_format_value(config.brain.auditor_model)}",
        f"brain_max_turns = {config.brain.brain_max_turns}",
        f"brain_executor = {_format_value(config.brain.brain_executor)}",
        f"operator_subscription_first = {_format_value(config.brain.operator_subscription_first)}",
        "",
        "[jev]",
        f"enabled = {_format_value(config.jev.enabled)}",
        f"endpoint = {_format_value(config.jev.endpoint)}",
        f"model = {_format_value(config.jev.model)}",
        f"timeout = {config.jev.timeout:g}",
        f"loop_threshold = {config.jev.loop_threshold:g}",
        "",
        "[clone_display]",
        "# Show a deployed clone's live terminal in a desktop window on this box.",
        "# Only addresses inside `segments` (and outside every denied network) are",
        "# ever displayed; identity is proved over SSH before anything opens.",
        f"enabled = {_format_value(config.clone_display.enabled)}",
        f"segments = {_format_array(config.clone_display.segments)}",
        f"deny = {_format_array(config.clone_display.deny)}",
        f"poll_interval = {config.clone_display.poll_interval:g}",
        f"terminal = {_format_value(config.clone_display.terminal)}",
        f"log = {_format_value(config.clone_display.log)}",
        "",
        "[lab_ssh]",
        "# Guest login for the malware-scripting MCP's deploy/test/persist tools.",
        "# These are exported into the session environment (the MCP child inherits",
        "# them) and are deliberately NOT written back by `evilkit config` — add",
        "# password and/or key to this table by hand. An already-set LAB_SSH_*",
        "# variable wins over anything here.",
        f"user = {_format_value(config.lab_ssh.user)}",
        '# password = "..."',
        '# key = "~/.ssh/id_ed25519_lab"',
    ]
    for target in config.clone_display.targets:
        lines += [
            "",
            "[[clone_display.targets]]",
            f"name = {_format_value(target.name)}",
            f"host = {_format_value(target.host)}",
            f"user = {_format_value(target.user)}",
            f"identity = {_format_value(target.identity)}",
            f"unit = {_format_value(target.unit)}",
        ]
    return "\n".join(lines) + "\n"


def save(config: Config, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dumps(config), encoding="utf-8")
    return target

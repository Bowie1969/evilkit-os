"""evilkit command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import appliance as appliance_mod
from . import build as build_mod
from . import commands
from . import config as config_mod

__all__ = ["main", "build_parser", "EXIT_OK", "EXIT_ERROR", "EXIT_USAGE"]

PROG = "evilkit"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

COMMANDS = (
    "run", "kimi", "qwen", "mesh", "osint", "patch-diff-poc", "script-harness",
    "scope", "log", "watch", "doctor", "theme", "config", "agent", "lessons",
    "learn", "hooks", "dashboard", "calls", "appliance", "version",
)

_EPILOG = """\
examples:
  evilkit                            prompt for a scope, then launch
  evilkit --scope 10.0.0.0/24        launch against one network
  evilkit -s 10.0.0.5,app.lan -y     non-interactive, two targets
  evilkit -s solo                    accept the locked-down default
  evilkit run --osint example.com    passive OSINT first, then pick the scope
  evilkit osint example.com          passive recon only; never launches
  evilkit --no-write -- -c           leave .mcp.json alone, resume a session
  evilkit scope show                 print the scope recorded in .mcp.json
  evilkit scope add 10.0.0.0/24      widen the record by one network
  evilkit scope remove 10.0.0.0/24   drop one network from the record
  evilkit log                        list the launches recorded locally
  evilkit watch                      watch the scope and alarm if it changes
  evilkit doctor                     check that everything is wired up

Every argument after `--` is passed straight through to the Kimi Code CLI.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Scope-gated launcher for the Kimi Code CLI.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = sub.add_parser(
        "run",
        help="set the scope and launch the Kimi Code CLI (default)",
        description="Set the authorized scope, then hand over to the Kimi Code CLI.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument(
        "-s",
        "--scope",
        metavar="TARGETS",
        help="comma-separated hosts, IPs or CIDRs; 'solo' for the locked-down default",
    )
    run.add_argument(
        "--deny",
        metavar="TARGETS",
        help=(
            "comma-separated targets to refuse even inside the scope; "
            "an empty value denies nothing (omit it to leave the record alone)"
        ),
    )
    run.add_argument(
        "--mcp-json",
        metavar="PATH",
        type=Path,
        help="path to .mcp.json (default: nearest one at or above the working directory)",
    )
    run.add_argument(
        "--no-write",
        "--read-only",
        dest="no_write",
        action="store_true",
        help="do not modify .mcp.json; only export the environment",
    )
    run.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="never prompt; fall back to the configured default scope",
    )
    run.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="report what would happen without writing or launching",
    )
    run.add_argument(
        "--allow-unscoped",
        action="store_true",
        help="launch even when the requested scope could not be recorded",
    )
    run.add_argument(
        "--allow-any",
        action="store_true",
        help="permit a /0 scope, which authorises every address",
    )
    run.add_argument(
        "--osint",
        nargs="*",
        metavar="SEED",
        help="run the passive OSINT stage on these seeds first, then choose "
             "the scope from the findings (interactive)",
    )
    run.add_argument(
        "--osint-accept",
        metavar="VALUES",
        help="with --osint: accept exactly these candidates as the scope "
             "(required instead of the prompt in --yes / non-tty mode)",
    )
    run.add_argument(
        "--no-osint-mcp",
        action="store_true",
        help="do not attach the osint MCP server to the launched session",
    )
    run.add_argument(
        "--strict",
        action="store_true",
        help="deprecated; an unrecordable scope is already fatal unless --allow-unscoped",
    )
    run.add_argument(
        "--no-audit",
        action="store_true",
        help="do not append this launch to the local log",
    )
    run.add_argument(
        "--window",
        action="store_true",
        help="open the session in a new desktop terminal window on this box",
    )

    osint_cmd = sub.add_parser(
        "osint",
        help="run the passive OSINT stage; never launches anything",
        description="Passive OSINT recon: public feeds and registries only. "
                    "Prints findings and writes osint-findings.json; the "
                    "candidates are only ever scope when you pass them to "
                    "`run --osint-accept` or pick them in the interactive stage.",
    )
    osint_cmd.add_argument("seeds", nargs="+", metavar="SEED",
                           help="domains, hostnames, emails, usernames, IPs or phone numbers")
    osint_cmd.add_argument("--only", metavar="TOOLS", help="comma-separated subset of tools to run")
    osint_cmd.add_argument("--skip", metavar="TOOLS", help="comma-separated tools to drop")
    osint_cmd.add_argument(
        "--json", dest="json_path", type=Path, metavar="PATH",
        help="write findings to PATH (default: osint-findings.json here)"
    )
    osint_cmd.add_argument(
        "--attach", action="store_true",
        help="also write the osint MCP server into the engagement .mcp.json, "
             "so the next kimi session here has the recon tools (never launches)"
    )

    pdp = sub.add_parser(
        "patch-diff-poc",
        help="turn a security-fix commit on GitHub into a scope-gated PoC script",
        description="Fetch a GitHub commit, derive a PocRecipe from its diff, "
                    "and emit a stdlib-only PoC request script that refuses to "
                    "run against a host not listed in the given scope file.",
    )
    pdp.add_argument("commit", metavar="COMMIT",
                     help="https://github.com/<owner>/<repo>/commit/<sha> or <owner>/<repo>@<sha>")
    pdp.add_argument("--out-dir", type=Path, default=None, metavar="DIR",
                     help="write recipe + script here (default: current directory)")
    pdp.add_argument("--flag-path", default="/opt/app/flag.txt", metavar="PATH",
                     help="flag path baked into eval-sink / path-traversal payloads")
    pdp.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS",
                     help="GitHub API timeout (default: 20)")
    pdp.add_argument("--print-only", action="store_true",
                     help="print the recipe JSON to stdout and do not write files")

    sh_cmd = sub.add_parser(
        "script-harness",
        help="run a script against an in-scope target in a disposable sandbox",
        description="Scope-gate a target, run a script inside bubblewrap (read-only "
                    "root, fresh workdir), and emit a JSON evidence record with the "
                    "output, exit code, filesystem diff, timing and optional pcap.",
    )
    sh_sub = sh_cmd.add_subparsers(dest="script_harness_command", metavar="ACTION")
    sh_cmd.set_defaults(script_harness_command="run")
    sh_run = sh_sub.add_parser("run", help="run a script against a target")
    sh_run.add_argument("script", metavar="SCRIPT", help="path to the script to run")
    sh_run.add_argument("--target", required=True, metavar="HOST",
                        help="target host the script will hit")
    sh_run.add_argument("--scope", default=None, metavar="TARGETS",
                        help="authorised scope (default: config default_scope)")
    sh_run.add_argument("--sandbox", choices=["auto", "bwrap", "none"], default="auto",
                        help="auto uses bubblewrap when installed (default: auto)")
    sh_run.add_argument("--timeout", type=float, default=60.0, metavar="SECONDS",
                        help="script timeout in seconds (default: 60)")
    sh_run.add_argument("--evidence-dir", type=Path, default=None, metavar="DIR",
                        help="write workdir + evidence here (default: current directory)")
    sh_run.add_argument("--pcap-iface", default=None, metavar="IFACE",
                        help="capture traffic to the target on this interface")
    sh_run.add_argument("args", nargs="*", metavar="ARGS",
                        help="arguments passed through to the script")

    appliance_cmd = sub.add_parser(
        "appliance",
        help="generate a bootable EvilKit OS appliance seed",
        description="Render a cloud-init NoCloud seed (user-data + meta-data), the "
                    "first-boot bootstrap script, and the systemd unit that turns a "
                    "bare image into an EvilKit OS node. Never builds or flashes an "
                    "image — it only writes the text artifacts.",
    )
    appliance_sub = appliance_cmd.add_subparsers(dest="appliance_command", metavar="ACTION")
    appliance_cmd.set_defaults(appliance_command="seed")
    seed_cmd = appliance_sub.add_parser("seed", help="write the appliance seed files")
    seed_cmd.add_argument("--hostname", default="evilkit-os", metavar="NAME")
    seed_cmd.add_argument("--user", default="operator", metavar="USER", help="admin user (key auth only)")
    seed_cmd.add_argument("--ssh-key", action="append", default=[], metavar="KEY",
                          help="public SSH key to authorise; repeat for several")
    seed_cmd.add_argument("--scope", default="solo", metavar="TARGETS",
                          help="authorized scope recorded at first boot (default: solo)")
    seed_cmd.add_argument("--mesh-leader", default=None, metavar="URL",
                          help="mesh leader URL to register with (requires --mesh-token)")
    seed_cmd.add_argument("--mesh-token", default=None, metavar="TOKEN",
                          help="mesh token, written 0600 root:root (requires --mesh-leader)")
    seed_cmd.add_argument("--install-source", default=appliance_mod.DEFAULT_INSTALL_SOURCE,
                          metavar="SPEC", help="pip install source for the operator system")
    seed_cmd.add_argument("--timezone", default="UTC", metavar="TZ")
    seed_cmd.add_argument("--out-dir", type=Path, default=Path("."), metavar="DIR",
                          help="write the seed files here (default: current directory)")

    build_cmd = appliance_sub.add_parser(
        "build",
        help="bake a Raspberry Pi drop image from a base image + wheel",
        description="Render the first-boot artifacts and write them into the boot "
                    "partition of a Raspberry Pi OS image, root-free via mtools. "
                    "Produces a bootable drop image, a bake dir and a manifest.",
    )
    build_cmd.add_argument("--hostname", required=True, metavar="NAME")
    build_cmd.add_argument("--user", default="pi", metavar="USER", help="admin user (default: pi)")
    build_cmd.add_argument("--ssh-key", action="append", default=[], metavar="KEY_OR_PATH",
                           required=True,
                           help="public SSH key (literal) or path to a .pub file; "
                                "repeat for several")
    build_cmd.add_argument("--scope", default="solo", metavar="TARGETS",
                           help="authorized scope recorded at first boot (default: solo)")
    build_cmd.add_argument("--mesh-leader", default=None, metavar="URL",
                           help="mesh leader URL (requires --mesh-token)")
    build_cmd.add_argument("--mesh-token", default=None, metavar="TOKEN",
                           help="mesh token, baked 0640 root:evilk (requires --mesh-leader)")
    build_cmd.add_argument("--eth0", default=None, metavar="CIDR",
                           help="static eth0 address, e.g. 10.99.50.60/24 (requires --gateway)")
    build_cmd.add_argument("--gateway", default=None, metavar="IP",
                           help="default gateway for --eth0")
    build_cmd.add_argument("--dns", default="1.1.1.1 9.9.9.9", metavar="SERVERS",
                           help="space-separated DNS servers (default: 1.1.1.1 9.9.9.9)")
    build_cmd.add_argument("--wifi-ssid", default=None, metavar="SSID",
                           help="Wi-Fi SSID (requires --wifi-psk)")
    build_cmd.add_argument("--wifi-psk", default=None, metavar="PSK",
                           help="Wi-Fi passphrase (requires --wifi-ssid)")
    build_cmd.add_argument("--wifi-country", default="AU", metavar="CC")
    build_cmd.add_argument("--wheel", required=True, type=Path, metavar="WHEEL",
                           help="the built evilkit-os wheel to bake")
    build_cmd.add_argument("--base-image", required=True, type=Path, metavar="IMAGE",
                           help="Raspberry Pi OS .img or .img.xz")
    build_cmd.add_argument("--output", required=True, type=Path, metavar="IMAGE",
                           help="where to write the drop image")
    build_cmd.add_argument("--boot-offset", type=int, default=build_mod.DEFAULT_BOOT_OFFSET,
                           metavar="BYTES",
                           help="byte offset of the FAT32 boot partition")
    build_cmd.add_argument("--dry-run", action="store_true",
                           help="render the bake dir + print the mtools plan, do not write the image")

    scope_cmd = sub.add_parser("scope", help="inspect or change the recorded scope")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command", metavar="ACTION")
    scope_cmd.set_defaults(
        scope_command=None, mcp_json=None, targets=None, allow_any=False, dry_run=False
    )
    scope_show = scope_sub.add_parser("show", help="print the scope recorded in .mcp.json")
    scope_show.add_argument("--mcp-json", metavar="PATH", type=Path)
    scope_clear = scope_sub.add_parser("clear", help="reset the scope to the locked-down default")
    scope_clear.add_argument("--mcp-json", metavar="PATH", type=Path)

    for action, blurb in (
        ("set", "replace the recorded scope"),
        ("add", "widen the recorded scope by the targets given"),
        ("remove", "narrow the recorded scope by the targets given"),
    ):
        editor = scope_sub.add_parser(action, help=blurb)
        editor.add_argument("targets", metavar="TARGETS",
                            help="comma-separated hosts, IPs or CIDRs; 'solo' for the locked-down default")
        editor.add_argument("--mcp-json", metavar="PATH", type=Path)
        editor.add_argument("--allow-any", action="store_true",
                            help="permit a /0 scope, which authorises every address")
        editor.add_argument("--dry-run", action="store_true",
                            help="report the change without writing it")

    log_cmd = sub.add_parser("log", help="list the launches recorded locally")
    log_cmd.add_argument("-n", "--limit", metavar="N", type=int, default=20,
                         help="show the newest N entries; 0 shows every entry (default: 20)")
    log_cmd.add_argument("--path", metavar="PATH", type=Path, help="read a different log file")
    log_cmd.add_argument("--json", action="store_true", help="print the raw log lines")

    watch_cmd = sub.add_parser("watch", help="watch the recorded scope and alarm if it changes")
    watch_cmd.add_argument("--mcp-json", metavar="PATH", type=Path,
                           help="path to .mcp.json (default: nearest one at or above the working directory)")
    watch_cmd.add_argument("--interval", metavar="SECONDS", type=float, default=1.0,
                           help="how often to sample the recorded scope (default: 1.0)")
    watch_cmd.add_argument("--once", action="store_true",
                           help="print a single frame and exit, for scripts and pipes")
    watch_cmd.add_argument("--no-color", action="store_true",
                           help="never use ANSI colour, even on a terminal")
    watch_cmd.add_argument("-n", "--limit", metavar="N", type=int, default=5,
                           help="how many recent launches to show; 0 shows none (default: 5)")

    sub.add_parser("doctor", help="check the local installation")

    theme_cmd = sub.add_parser("theme", help="manage the bundled colour theme")
    theme_cmd.add_argument("action", nargs="?", choices=("install", "status"), default="status")
    theme_cmd.add_argument("--force", action="store_true", help="overwrite an existing theme")

    config_cmd = sub.add_parser("config", help="show configuration")
    config_sub = config_cmd.add_subparsers(dest="config_command", metavar="ACTION")
    config_sub.add_parser("path", help="print the config file location")
    config_sub.add_parser("show", help="print the effective configuration")
    config_sub.add_parser("init", help="write a commented default config file")

    agent_cmd = sub.add_parser(
        "agent",
        help="run a versioned Kimi K3 augmentation config against a target",
        description="Load a versioned agent config and run it through the Kimi Code CLI.",
    )
    agent_cmd.add_argument("--config", metavar="PATH", type=Path, help="path to the agent config TOML file")
    agent_cmd.add_argument("--target", metavar="HOST:PORT", help="authorized target for the agent to assess")
    agent_cmd.add_argument("--interactive", action="store_true",
                           help="after the first response, allow follow-up prompts")
    agent_cmd.add_argument("--list", action="store_true", help="list built-in agent configs and exit")
    agent_cmd.add_argument("--mcp-json", metavar="PATH", type=Path,
                           help="path to the .mcp.json whose recorded scope gates this run")
    agent_cmd.add_argument("--no-audit", action="store_true", help="do not append this launch to the local log")

    sub.add_parser("kimi", add_help=False, help="launch the scoped Kimi CLI adapter")
    sub.add_parser("qwen", add_help=False, help="launch the scoped Qwen CLI adapter")
    sub.add_parser("mesh", add_help=False, help="coordinate explicitly enrolled lab workers and nodes")

    lessons_cmd = sub.add_parser("lessons", help="inspect or add durable operator lessons")
    lessons_sub = lessons_cmd.add_subparsers(dest="lessons_command", metavar="ACTION")
    lessons_sub.add_parser("show", help="print the lessons injected into Kimi and Qwen")
    lessons_sub.add_parser("path", help="print the lessons file path")
    lessons_add = lessons_sub.add_parser("add", help="append a manually reviewed lesson")
    lessons_add.add_argument("title")
    lessons_add.add_argument("body")
    lessons_add.add_argument("--source")

    learn_cmd = sub.add_parser("learn", help="inspect or feed the reversible self-training loop")
    learn_sub = learn_cmd.add_subparsers(dest="learn_command", metavar="ACTION")
    learn_sub.add_parser("status", help="show session metrics by lessons generation")
    learn_sub.add_parser("rollback", help="remove the most recent automatic lesson batch")
    learn_ingest = learn_sub.add_parser("ingest", help="learn from a hook session JSONL file")
    learn_ingest.add_argument("path", type=Path)
    learn_ingest.add_argument("--run-id")
    learn_ingest.add_argument("--dry-run", action="store_true")

    hooks_cmd = sub.add_parser("hooks", help="install or inspect the shared Kimi/Qwen event bridge")
    hooks_cmd.add_argument("hooks_action", nargs="?", choices=("install", "status"), default="status")
    hooks_cmd.add_argument("--engine", choices=("all", "kimi", "qwen"), default="all")

    dashboard_cmd = sub.add_parser("dashboard", help="inspect a Keystone run fed by EvilKit")
    dashboard_cmd.add_argument("dashboard_action", nargs="?", choices=("status", "tail"), default="status")
    dashboard_cmd.add_argument("--run-dir", type=Path, required=True)
    dashboard_cmd.add_argument("-n", "--limit", type=int, default=20)

    calls_cmd = sub.add_parser(
        "calls",
        help="classify the tool calls in a session log",
        description="Read a session log (EvilKit's own, the Kimi wire, or a Qwen "
                    "transcript) and report what each tool call actually did: a real "
                    "result, a refusal, a timeout, an auth failure, or nothing usable.",
    )
    calls_sub = calls_cmd.add_subparsers(dest="calls_command", metavar="ACTION")
    calls_cmd.set_defaults(calls_command=None, path=None, json=False, limit=15, session_dir=None)
    calls_classify = calls_sub.add_parser("classify", help="classify every call in a log")
    calls_classify.add_argument("path", metavar="LOG", help="session log to read")
    calls_classify.add_argument("--json", action="store_true", help="print the full report as JSON")
    calls_classify.add_argument("-n", "--limit", type=int, default=15,
                                help="how many problem calls and repeats to list (default: 15)")

    calls_verify = calls_sub.add_parser(
        "verify-run",
        help="check that a run's session log, dashboard events and journal agree",
        description="Compare what a run recorded about itself with what the dashboard "
                    "and the scorer's journal recorded, and report every disagreement.",
    )
    calls_verify.add_argument("path", metavar="RUN_DIR", help="prepared run directory")
    calls_verify.add_argument("--json", action="store_true", help="print the full report as JSON")
    calls_verify.add_argument("--session-dir", type=Path, metavar="PATH",
                              help="where the harness session logs live "
                                   "(default: $XDG_STATE_HOME/evilkimi/sessions)")

    sub.add_parser("version", help="print the version")

    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # These adapters own their option syntax. Dispatch before this parser touches
    # their arguments so new upstream flags continue to pass through unchanged.
    if raw and raw[0] == "kimi":
        from . import kimi
        return kimi.main(raw[1:])
    if raw and raw[0] == "qwen":
        from . import qwen
        return qwen.main(raw[1:])
    if raw and raw[0] == "mesh":
        from . import mesh
        return mesh.main(raw[1:])

    # Split on the first standalone "--" by hand: everything after it belongs to
    # the Kimi Code CLI and must survive argparse untouched.
    if "--" in raw:
        cut = raw.index("--")
        raw, passthrough = raw[:cut], raw[cut + 1 :]
    else:
        passthrough = []

    if not raw:
        raw = ["run"]
    elif raw[0] not in COMMANDS and raw[0] not in ("-h", "--help", "-V", "--version"):
        raw = ["run", *raw]

    parser = build_parser()
    args = parser.parse_args(raw)
    args.passthrough = passthrough

    if getattr(args, "command", None) in (None, "version"):
        if args.command is None:
            parser.print_help()
            return EXIT_OK
        print(f"{PROG} {__version__}")
        return EXIT_OK

    config, problems = config_mod.load()

    if args.command == "run":
        return commands.cmd_run(args, config, problems)
    if args.command == "osint":
        return commands.cmd_osint(args, config, problems)
    if args.command == "patch-diff-poc":
        return commands.cmd_patch_diff_poc(args, config, problems)
    if args.command == "script-harness":
        return commands.cmd_script_harness(args, config, problems)
    if args.command == "scope":
        return commands.cmd_scope(args, config)
    if args.command == "log":
        return commands.cmd_log(args, config)
    if args.command == "watch":
        return commands.cmd_watch(args, config)
    if args.command == "doctor":
        return commands.cmd_doctor(config, problems)
    if args.command == "theme":
        return commands.cmd_theme(args)
    if args.command == "config":
        return commands.cmd_config(args, config, problems)
    if args.command == "agent":
        return commands.cmd_agent(args, config)
    if args.command == "lessons":
        return commands.cmd_lessons(args)
    if args.command == "learn":
        return commands.cmd_learn(args)
    if args.command == "hooks":
        return commands.cmd_hooks(args)
    if args.command == "dashboard":
        return commands.cmd_dashboard(args)
    if args.command == "calls":
        return commands.cmd_calls(args)
    if args.command == "appliance":
        return commands.cmd_appliance(args, config, problems)

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

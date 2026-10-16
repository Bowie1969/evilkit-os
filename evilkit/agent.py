"""Versioned agent configs that augment Kimi K3 for pentest engagements.

A config is a TOML file with:

    version = "v1"
    name = "baseline"
    system_prompt = "You are a security tester..."
    methodology = "1. Reconnaissance..."
    tool_suggestions = "Prefer curl and rustscan..."
    output_format = "Print each finding as: FOUND ..."
    follow_up_prompt = "What would you do next?"

The :func:`run` function builds a full prompt from the config and target,
then invokes the Kimi Code CLI in one-shot prompt mode. In interactive mode
it opens a simple REPL so the operator can steer the agent if it stalls.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import config as config_mod

__all__ = ["AgentConfig", "load_config", "build_prompt", "run", "builtin_configs"]


@dataclass
class AgentConfig:
    """A versioned augmentation config for a Kimi K3 agent run."""

    version: str = "v0"
    name: str = "unnamed"
    system_prompt: str = ""
    methodology: str = ""
    tool_suggestions: str = ""
    output_format: str = ""
    follow_up_prompt: str = "What would you like to do next?"


def _normalise(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())


def load_config(path: Path) -> AgentConfig:
    """Load and validate an agent config TOML file."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("agent config must be a TOML table")

    required = {"version", "name"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"agent config missing required keys: {sorted(missing)}")

    return AgentConfig(
        version=str(data.get("version", "v0")),
        name=str(data.get("name", "unnamed")),
        system_prompt=_normalise(str(data.get("system_prompt", ""))),
        methodology=_normalise(str(data.get("methodology", ""))),
        tool_suggestions=_normalise(str(data.get("tool_suggestions", ""))),
        output_format=_normalise(str(data.get("output_format", ""))),
        follow_up_prompt=_normalise(str(data.get("follow_up_prompt", ""))),
    )


def builtin_configs() -> list[Path]:
    """Return the built-in agent config files shipped with evilkit."""
    here = Path(__file__).resolve().parent
    configs_dir = here / "configs" / "agent"
    if not configs_dir.is_dir():
        return []
    return sorted(p for p in configs_dir.iterdir() if p.suffix == ".toml")


def build_prompt(config: AgentConfig, target: str) -> str:
    """Assemble the full prompt sent to Kimi K3."""
    parts = []
    if config.system_prompt:
        parts.append(config.system_prompt)
    parts.append(f"Authorized target: {target}")
    if config.methodology:
        parts.append(f"Methodology:\n{config.methodology}")
    if config.tool_suggestions:
        parts.append(f"Tool guidance:\n{config.tool_suggestions}")
    if config.output_format:
        parts.append(f"Required output format:\n{config.output_format}")
    parts.append(
        "Begin the engagement. Report any flags, endpoints, or evidence you discover."
    )
    return "\n\n".join(parts)


def _resolve_kimi_bin(config: config_mod.Config) -> str:
    """Find the Kimi Code CLI binary, using the same logic as the launcher."""
    kimi = config.resolved_kimi_bin()
    if Path(kimi).is_file() or shutil.which(kimi):
        return kimi
    raise FileNotFoundError(f"cannot find the Kimi Code CLI ({kimi!r})")


def _run_kimi_prompt(
    kimi: str,
    prompt: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 300,
) -> tuple[str, int]:
    """Run `kimi -p <prompt>` and return (combined stdout/stderr, exit code)."""
    try:
        proc = subprocess.run(
            [kimi, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return f"[evilkit: kimi -p timed out after {int(timeout)}s]", 124
    except FileNotFoundError as exc:
        return f"[evilkit: cannot start kimi: {exc}]", 127
    output = (proc.stdout or "") + (proc.stderr or "")
    return output, proc.returncode


def run(
    config_path: Path,
    target: str,
    *,
    interactive: bool = False,
    config: config_mod.Config | None = None,
    env: dict[str, str] | None = None,
) -> int:
    """Run the agent config against the target.

    In non-interactive mode the built prompt is sent once via ``kimi -p`` and
    the response is printed. In interactive mode the response is printed and
    the user is invited to type follow-up prompts until they send an empty
    line.
    """
    agent_config = load_config(config_path)
    kimi = _resolve_kimi_bin(config or config_mod.Config())
    prompt = build_prompt(agent_config, target)

    print(f"evilkit agent {agent_config.version}-{agent_config.name}")
    print(f"evilkit agent target -> {target}")

    output, rc = _run_kimi_prompt(kimi, prompt, env=env)
    print(output)

    if not interactive:
        return rc

    # Interactive fallback: let the operator steer a stalled agent.
    print("\n--- interactive mode: type a follow-up prompt, or press Enter to exit ---")
    while True:
        try:
            follow_up = input(
                f"[{agent_config.version}-{agent_config.name}] {agent_config.follow_up_prompt} "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not follow_up.strip():
            break
        follow_output, rc = _run_kimi_prompt(kimi, follow_up, env=env)
        print(follow_output)

    return rc

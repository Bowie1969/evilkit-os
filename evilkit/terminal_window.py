"""Pop up a local desktop terminal window showing a running EvilKit clone/session."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

__all__ = [
    "display_available",
    "resolve_terminal_emulator",
    "build_terminal_argv",
    "spawn_terminal_window",
    "raise_terminal_window",
    "ClonePopupManager",
]

_TERMINAL_CANDIDATES = (
    "konsole",
    "gnome-terminal",
    "xfce4-terminal",
    "mate-terminal",
    "qterminal",
    "kitty",
    "alacritty",
    "tilix",
    "xterm",
    "x-terminal-emulator",
)


def display_available(env: dict[str, str] | None = None) -> bool:
    """Return True if an X11 or Wayland display is present in the environment."""
    source = os.environ if env is None else env
    return bool(source.get("DISPLAY", "").strip() or source.get("WAYLAND_DISPLAY", "").strip())


def resolve_terminal_emulator(explicit: str | None = None) -> str | None:
    """Find a local GUI terminal emulator binary."""
    req = explicit or os.environ.get("EVILKIT_TERMINAL_BIN")
    if req:
        expanded = os.path.expanduser(req)
        if os.sep in expanded:
            return expanded if Path(expanded).is_file() else None
        return shutil.which(expanded)

    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
    candidates = list(_TERMINAL_CANDIDATES)
    if "GNOME" in desktop and "gnome-terminal" in candidates:
        candidates.remove("gnome-terminal")
        candidates.insert(0, "gnome-terminal")

    for name in candidates:
        found = shutil.which(name)
        if found:
            return found
    return None


def build_terminal_argv(
    emulator: str,
    command: list[str],
    *,
    title: str = "EvilKit Clone",
    hold: bool = False,
    wait: bool = False,
    cwd: Path | None = None,
) -> list[str]:
    """Build the command-line argv to launch ``command`` inside ``emulator``."""
    base = Path(emulator).name
    # Resolve symlinks like x-terminal-emulator -> zutty/xterm/konsole when possible
    try:
        real_base = Path(emulator).resolve().name
    except OSError:
        real_base = base
    kind = real_base if base == "x-terminal-emulator" else base

    if kind == "konsole":
        argv = [emulator, "--separate"]
        if hold:
            argv.append("--hold")
        if cwd is not None:
            argv.extend(["--workdir", str(cwd)])
        argv.extend(["-p", f"tabtitle={title}", "-e", *command])
        return argv

    if kind == "gnome-terminal":
        argv = [emulator, f"--title={title}"]
        if wait:
            argv.append("--wait")
        if cwd is not None:
            argv.extend([f"--working-directory={cwd}"])
        argv.extend(["--", *command])
        return argv

    if kind in ("xfce4-terminal", "mate-terminal"):
        argv = [emulator, "--title", title]
        if hold:
            argv.append("--hold")
        if cwd is not None:
            argv.extend(["--working-directory", str(cwd)])
        argv.extend(["-x", *command])
        return argv

    if kind in ("kitty", "alacritty"):
        argv = [emulator, "--title", title]
        if hold:
            argv.append("--hold")
        if cwd is not None:
            argv.extend(["--working-directory", str(cwd)])
        argv.extend(["-e", *command])
        return argv

    if kind == "xterm":
        argv = [emulator, "-T", title]
        if hold:
            argv.append("-hold")
        argv.extend(["-e", *command])
        return argv

    # Generic fallback (zutty, qterminal, tilix, etc.)
    return [emulator, "-e", *command]


def spawn_terminal_window(
    command: list[str],
    *,
    title: str = "EvilKit Clone",
    hold: bool = False,
    wait: bool = False,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    emulator: str | None = None,
) -> subprocess.Popen | None:
    """Spawn a GUI terminal window running ``command``.

    Returns the ``Popen`` handle (or None if no display or terminal emulator is available).
    """
    run_env = dict(os.environ if env is None else env)
    if not display_available(run_env):
        return None
    term = resolve_terminal_emulator(emulator)
    if not term:
        return None
    argv = build_terminal_argv(
        term,
        command,
        title=title,
        hold=hold,
        wait=wait,
        cwd=cwd,
    )
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=run_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    if wait:
        proc.wait()
    return proc


def raise_terminal_window(pid: int) -> bool:
    """Bring an existing clone terminal to the front on an X11 desktop.

    A clone's terminal normally stays open between tasks. Merely deduplicating
    that window meant a new deployment happened silently behind other windows;
    raising it makes each deployment visible without opening duplicates.
    """
    if not display_available() or not isinstance(pid, int) or pid <= 0:
        return False
    xdotool = shutil.which("xdotool")
    if not xdotool:
        return False
    try:
        found = subprocess.run(
            [xdotool, "search", "--pid", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        window_ids = [line.strip() for line in found.stdout.splitlines() if line.strip().isdigit()]
        if found.returncode != 0 or not window_ids:
            return False
        window = window_ids[-1]
        for action in ("windowmap", "windowraise", "windowactivate"):
            result = subprocess.run(
                [xdotool, action, window],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
            if result.returncode != 0:
                return False
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


class ClonePopupManager:
    """Tracks active popup terminal windows per mesh clone so each clone pops up one live window."""

    def __init__(self, *, enabled: bool = True, emulator: str | None = None):
        self.enabled = enabled
        self.emulator = emulator
        self._procs: dict[str, subprocess.Popen] = {}

    def is_active(self, name: str) -> bool:
        proc = self._procs.get(name)
        return proc is not None and proc.poll() is None

    def popup_for_worker(
        self,
        name: str,
        leader_url: str,
        token_file: Path,
        *,
        python_executable: str | None = None,
    ) -> subprocess.Popen | None:
        """Open a live watch terminal window for worker/clone ``name`` if not already open."""
        if not self.enabled:
            return self._procs.get(name)
        if self.is_active(name):
            raise_terminal_window(self._procs[name].pid)
            return self._procs[name]
        import sys

        py = python_executable or sys.executable
        cmd = [
            py,
            "-m",
            "evilkit",
            "mesh",
            "watch",
            "--leader",
            leader_url,
            "--token-file",
            str(token_file.expanduser().resolve()),
            "--worker",
            name,
            "--wait",
        ]
        proc = spawn_terminal_window(
            cmd,
            title=f"EvilKit Clone: {name}",
            hold=True,
            emulator=self.emulator,
        )
        if proc is not None:
            self._procs[name] = proc
        return proc

    def close_all(self) -> None:
        for proc in self._procs.values():
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        self._procs.clear()

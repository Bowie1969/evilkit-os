"""The lab dashboard's run controls, as a client.

Two callers reach the board through here: the MCP surface the operator uses
(:mod:`evilkit.dashboard_mcp`) and the launcher's own automation
(``[dashboard] auto``). Keeping one client means one implementation of the wire
shape, one timeout, and one place that decides what "a run is already being
tracked" means.

What the controls are: the board's three buttons run fixed, pre-registered
scripts in the Keystone tree, and those scripts are *bookkeeping* — start marks
the newest prepared run as the one being tracked, stop marks the tracked run
finished. They do not launch or tear down the range, they do not start or stop
an operator session, and nothing here puts traffic on an engagement target.

What the controls are not: authenticated. The board's run-control endpoints
carry a same-origin check, which is CSRF-shaped rather than auth, so reaching the
configured URL is the whole authority.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import dashboard_telemetry

URL_ENV = "EVILKIT_DASHBOARD_URL"
TIMEOUT_ENV = "EVILKIT_DASHBOARD_TIMEOUT"
RUN_DIR_ENV = "EVILKIT_DASHBOARD_RUN_DIR"

#: The dashboard's run-control routes, keyed by the action it knows them as. The
#: path is matched exactly (no query string) and the script each one runs is
#: fixed in the dashboard's own config — nothing from the request is passed on.
CONTROL_ROUTES = {"start": "/api/run/start", "stop": "/api/run/stop"}

#: Actions whose completion means a run is being tracked, in the board's own
#: vocabulary. `reset` is not offered as a tool, but the board reports it as its
#: last control, so it has to be read correctly when deciding whether to start
#: tracking again.
TRACKING_ACTIONS = ("start", "reset")

#: Terminal state the board reads as "this run is over but still worth reading".
#: `find_live_run` keeps a run in view for ten minutes after this is written,
#: then it retires to the idle view. "stopped" would read as torn down.
FINISHED_STATE = "finished"

#: What the board's last control implies about whether a run is being tracked.
#: The controls are bookkeeping (`keystone/run_control.py`): they mark a prepared
#: run's dashboard status, and never touch the range or the operator session.
TRACKING_ACTIVE = "active"
TRACKING_NONE = "none"
TRACKING_BUSY = "busy"
TRACKING_UNKNOWN = "unknown"

DEFAULT_TIMEOUT = 5.0

#: The board launches the control script and answers immediately, so a bare POST
#: replies "running" whether the control will work or not. start and stop are
#: file bookkeeping that settle in well under a second, so a short wait turns
#: that hopeful answer into the board's own verdict — "succeeded", or "failed"
#: carrying the script's own reason (for example "a run is already being
#: tracked"). `settle <= 0` answers with whatever the POST returned.
CONTROL_SETTLE_SECONDS = 6.0
CONTROL_POLL_SECONDS = 0.25


class DashboardError(Exception):
    """A dashboard control could not be carried out."""


def base_url() -> str:
    """The dashboard's base URL, or a refusal explaining what to set.

    There is no default address: a guessed host would either fail obscurely or,
    worse, succeed against something that is not the intended board.
    """
    value = os.environ.get(URL_ENV, "").strip().rstrip("/")
    if not value:
        raise DashboardError(
            f"no dashboard URL is configured: set `url` in the evilkit config's [dashboard] "
            f"table, or export {URL_ENV} (for example http://127.0.0.1:8793)"
        )
    if not value.startswith(("http://", "https://")):
        raise DashboardError(f"{URL_ENV}={value!r} must be an http:// or https:// URL")
    return value


def timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if value > 0 else DEFAULT_TIMEOUT


def request(path: str, *, method: str = "GET") -> dict:
    """Call one dashboard route and return its JSON body.

    A POST is sent with an empty body and no ``Origin`` header: the dashboard
    refuses cross-origin POSTs, and any non-browser client passes that check.
    """
    base = base_url()
    url = base + path
    # `data=b""` is what makes this a POST with Content-Length: 0; None would
    # silently become a GET against a GET-only route.
    data = b"" if method == "POST" else None
    call = urllib.request.Request(url, data=data, method=method)
    try:
        with urllib.request.urlopen(call, timeout=timeout()) as response:
            body = response.read(65536)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            payload = json.loads(exc.read(4096))
            if isinstance(payload, dict):
                detail = str(payload.get("error") or payload.get("message") or "")
        except (OSError, ValueError):
            detail = ""
        if exc.code == 404:
            raise DashboardError(
                f"the dashboard has no {path} route (HTTP 404) — it is probably an older "
                f"build than this tool expects"
            ) from exc
        raise DashboardError(detail or f"{url} answered HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise DashboardError(f"the dashboard at {base} is not reachable: {exc.reason}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise DashboardError(f"the dashboard at {base} did not answer within {timeout():g}s") from exc
    except OSError as exc:
        raise DashboardError(f"could not reach the dashboard at {base}: {exc}") from exc
    if not body:
        return {}
    try:
        value = json.loads(body)
    except ValueError as exc:
        raise DashboardError(f"{url} returned something that is not JSON: {exc}") from exc
    return value if isinstance(value, dict) else {"value": value}


def status() -> dict:
    """The board's control-relevant state, without the topology it also carries."""
    sample = request("/api/status")
    projected = {key: sample[key] for key in ("status", "control_run", "controls") if key in sample}
    if not projected:
        projected = {"status": sample.get("status", sample)}
    projected["dashboard"] = base_url()
    return projected


def tracking_state(sample: dict | None = None) -> str:
    """What the board's own last control says about whether a run is tracked.

    The board tracks the control it ran and whether it succeeded, which is the
    only tracking-state signal it publishes. A run the board never controlled is
    therefore TRACKING_UNKNOWN, and the caller decides what to do about that.
    """
    if sample is None:
        sample = status()
    control = sample.get("control_run") or {}
    if not isinstance(control, dict) or not control.get("action"):
        return TRACKING_UNKNOWN
    if control.get("status") == "running":
        return TRACKING_BUSY
    if control.get("status") != "succeeded":
        return TRACKING_UNKNOWN
    if control.get("action") in TRACKING_ACTIONS:
        return TRACKING_ACTIVE
    if control.get("action") == "stop":
        return TRACKING_NONE
    return TRACKING_UNKNOWN


def run_dir() -> Path | None:
    """The dashboard run bound to this session, if one is."""
    return dashboard_telemetry.DashboardTelemetry().run_dir


def _record(action: str, outcome: str, detail: dict) -> None:
    """Append one control call to the bound run's journal, best effort.

    The control has already happened by the time this runs, so a journal that
    cannot be written must not be reported as a failed control — but the
    operator's own lab actions belong next to its target actions, so a teardown
    mid-run is attributable afterwards.
    """
    telemetry = dashboard_telemetry.DashboardTelemetry()
    if not telemetry.enabled:
        return
    record = {
        "run_id": telemetry.run_dir.name,
        "ts": time.time(),
        "source": "evilkit",
        "kind": "control",
        "action": action,
        "status": outcome,
    }
    for key in ("message", "pid", "script"):
        if detail.get(key) is not None:
            record[key] = detail[key]
    try:
        with telemetry._locked():
            telemetry._append(telemetry.run_dir / "journal.jsonl", record)
    except OSError:
        return


def _settle(result: dict, settle: float) -> dict:
    """Wait briefly for the board to finish the control it just started.

    The board answers a control request as soon as it has launched the script, so
    the POST's own reply is "running" even for a control that is about to fail
    (for example a start refused because a run is already being tracked). Waiting
    for the board's verdict is what makes the reply worth reading; if it is still
    running at the deadline the initial answer is returned unchanged.
    """
    if settle <= 0 or result.get("status") != "running":
        return result
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        time.sleep(CONTROL_POLL_SECONDS)
        try:
            current = status().get("control_run") or {}
        except DashboardError:
            return result
        if not isinstance(current, dict):
            return result
        if current.get("pid") == result.get("pid") and current.get("status") != "running":
            return current
    return result


def control(action: str, *, settle: float = CONTROL_SETTLE_SECONDS) -> dict:
    """Run one of the dashboard's fixed run-control scripts.

    The scripts are bookkeeping, not range actions: start marks the newest
    prepared run as being tracked, stop marks the tracked run finished, and
    neither starts, stops or touches the range or the operator session.
    """
    path = CONTROL_ROUTES.get(action)
    if path is None:
        raise DashboardError(f"unknown control: {action}")
    result = dict(request(path, method="POST"))
    result["action"] = action
    result["dashboard"] = base_url()
    result = _settle(result, settle)
    _record(action, str(result.get("status") or "accepted"), result)
    return result


def auto_start() -> dict:
    """Start tracking a prepared run for this launch, or explain why not.

    ``{"started": True, "control": ..., "tracking_before": ...}`` when this call
    started it, otherwise ``{"started": False, "reason": ...}``. Tracking is left
    alone when the board is busy with another control, and when the board's own
    last control says a run is already being tracked — `keystone.run_control.start`
    refuses that case outright ("a run is already being tracked"), so asking would
    only turn a no-op into a failure.

    A run the board has never controlled reads as TRACKING_UNKNOWN and *is*
    started: the launch wants its run on the board, and the board itself is the
    thing that decides which prepared run that is.
    """
    state = tracking_state()
    if state == TRACKING_BUSY:
        return {"started": False, "reason": "the board is already running a control",
                "tracking": state}
    if state == TRACKING_ACTIVE:
        return {"started": False, "reason": "a run is already being tracked",
                "tracking": state}
    result = control("start")
    return {"started": True, "control": result, "tracking_before": state}


def auto_stop(started_by_us: bool) -> dict:
    """Stop tracking the run at session end, but only if this launch started it.

    The guard is the whole point: the board tracks one run at a time and the
    control acts on whichever that is, so an unconditional stop here would end
    another session's tracking — or one the operator started by hand.
    """
    if not started_by_us:
        return {"stopped": False, "reason": "this launch did not start tracking a run"}
    return {"stopped": True, "control": control("stop")}


def end_run() -> dict:
    """Write the terminal state for the run bound to this session.

    Nothing is stopped: the range and the session stay exactly as they are. This
    only tells the board the run is over, using the same lock and atomic write as
    the telemetry emitter so the two cannot interleave.
    """
    telemetry = dashboard_telemetry.DashboardTelemetry()
    if telemetry.run_dir is None:
        raise DashboardError(
            "no dashboard run is bound to this session, so there is nothing to finish: "
            "launch with --dashboard-run-dir (or set EVILKIT_DASHBOARD_RUN_DIR)"
        )
    dashboard = telemetry.run_dir / "dashboard"
    if not dashboard.is_dir():
        raise DashboardError(
            f"{dashboard} does not exist: {telemetry.run_dir} is not a prepared dashboard run"
        )

    status_path = dashboard / "status.json"
    try:
        status_value = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status_value = {}
    if not isinstance(status_value, dict):
        status_value = {}

    now = time.time()
    status_value.update(
        {
            "run_id": status_value.get("run_id") or telemetry.run_dir.name,
            "state": FINISHED_STATE,
            "updated_at": now,
            "ended_at": now,
            # `finished` in the range's own vocabulary (keystone.run_control.stop
            # writes the same field), so the record reads the same way however the
            # run was ended.
            "finished": datetime.datetime.fromtimestamp(
                now, datetime.timezone.utc).isoformat(),
        }
    )
    try:
        with telemetry._locked():
            telemetry._atomic_json(status_path, status_value)
            telemetry._append(
                telemetry.run_dir / "journal.jsonl",
                {
                    "run_id": status_value["run_id"],
                    "ts": now,
                    "source": "evilkit",
                    "kind": "control",
                    "action": "end_run",
                    "status": FINISHED_STATE,
                    "run_dir": str(telemetry.run_dir),
                },
            )
    except OSError as exc:
        raise DashboardError(f"could not write {status_path}: {exc}") from exc

    return {
        "run_id": status_value["run_id"],
        "run_dir": str(telemetry.run_dir),
        "state": FINISHED_STATE,
        "status_file": str(status_path),
        "note": (
            "the run is marked finished; the board keeps a finished run in view for ten "
            "minutes, then falls back to the idle view. Nothing was stopped."
        ),
    }

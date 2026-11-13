"""In-process job registry for asynchronous scans with live progress steps."""

from __future__ import annotations

import copy
import threading
import uuid
from datetime import datetime, timezone

MAX_JOBS = 200
_locks = threading.Lock()
_jobs: dict[str, dict] = {}


def _normalise_steps(steps: list) -> list[dict]:
    normalised = []
    for step in steps:
        if isinstance(step, dict):
            key, label = step.get("key"), step.get("label")
        else:
            key, label = step[0], step[1]
        normalised.append({"key": key, "label": label, "status": "pending", "detail": ""})
    return normalised


def create_job(kind: str, steps: list) -> str:
    job_id = uuid.uuid4().hex
    with _locks:
        _trim()
        _jobs[job_id] = {
            "id": job_id,
            "kind": kind,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "steps": _normalise_steps(steps),
            "result_url": None,
            "error": None,
        }
    return job_id


def set_job_running(job_id: str) -> None:
    with _locks:
        if job_id in _jobs:
            _jobs[job_id]["status"] = "running"


def set_step(job_id: str, key: str, status: str, detail: str = "") -> None:
    with _locks:
        job = _jobs.get(job_id)
        if not job:
            return
        for step in job["steps"]:
            if step["key"] == key:
                step["status"] = status
                if detail:
                    step["detail"] = str(detail)[:220]
                break


def finish_job(job_id: str, result_url: str) -> None:
    with _locks:
        job = _jobs.get(job_id)
        if not job:
            return
        job["status"] = "done"
        job["result_url"] = result_url


def fail_job(job_id: str, message: str) -> None:
    with _locks:
        job = _jobs.get(job_id)
        if not job:
            return
        job["status"] = "error"
        job["error"] = str(message)[:500]
        for step in job["steps"]:
            if step["status"] == "running":
                step["status"] = "failed"


def get_job(job_id: str) -> dict | None:
    with _locks:
        job = _jobs.get(job_id)
        return copy.deepcopy(job) if job else None


def _trim() -> None:
    if len(_jobs) <= MAX_JOBS:
        return
    ordered = sorted(_jobs.values(), key=lambda j: j["created_at"])
    for job in ordered[: len(_jobs) - MAX_JOBS]:
        _jobs.pop(job["id"], None)

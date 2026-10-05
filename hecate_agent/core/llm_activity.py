"""A live record of provider calls, so a long run can be watched while it happens.

Usage totals reach the caller only when a whole stage returns, which for a
local model can be many minutes after the first call was sent. When
``HECATE_LLM_CALL_LOG`` names a file, every provider call appends a line as
it starts and another as it ends; without it nothing is written.
"""

import functools
import json
import os
import threading
import time
from typing import Any, Callable, Dict, List

CALL_LOG_ENV = "HECATE_LLM_CALL_LOG"

_write_lock = threading.Lock()
_in_call = threading.local()


def _append(record: Dict[str, Any]) -> None:
    path = os.environ.get(CALL_LOG_ENV)
    if not path:
        return
    try:
        line = json.dumps({"ts": round(time.time(), 3), **record})
        with _write_lock, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except (OSError, TypeError, ValueError):
        pass  # watching a run must never be what breaks it


def recorded(complete: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a provider's ``complete`` so each call is logged when the call log is on."""

    @functools.wraps(complete)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        # A provider that extends another's ``complete`` is still making one call.
        if not os.environ.get(CALL_LOG_ENV) or getattr(_in_call, "active", False):
            return complete(self, *args, **kwargs)
        _append({"event": "start"})
        _in_call.active = True
        try:
            response = complete(self, *args, **kwargs)
        except BaseException:
            _append({"event": "error"})
            raise
        finally:
            _in_call.active = False
        _append(
            {
                "event": "end",
                "model": getattr(response, "model", ""),
                "input_tokens": getattr(response, "input_tokens", 0),
                "output_tokens": getattr(response, "output_tokens", 0),
                "duration_ms": getattr(response, "duration_ms", 0),
                "cost_usd": getattr(response, "cost_usd", 0.0),
            }
        )
        return response

    return wrapper


def summarize_calls(lines: List[str]) -> Dict[str, Any]:
    """Totals for a call log's lines; empty when they hold no call at all."""
    started = failed = 0
    ended: List[Dict[str, Any]] = []
    last_start = last_end = 0.0
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        event, ts = record.get("event"), float(record.get("ts") or 0.0)
        if event == "start":
            started += 1
            last_start = max(last_start, ts)
        elif event == "error":
            failed += 1
        elif event == "end":
            ended.append(record)
            last_end = max(last_end, ts)
    if not started:
        return {}
    return {
        "llm_calls": len(ended),
        "in_flight": max(0, started - len(ended) - failed),
        "failed": failed,
        "input_tokens": sum(int(r.get("input_tokens") or 0) for r in ended),
        "output_tokens": sum(int(r.get("output_tokens") or 0) for r in ended),
        "cost_usd": sum(float(r.get("cost_usd") or 0.0) for r in ended),
        "models": sorted({str(r["model"]) for r in ended if r.get("model")}),
        "last_start": last_start,
        "last_end": last_end,
    }


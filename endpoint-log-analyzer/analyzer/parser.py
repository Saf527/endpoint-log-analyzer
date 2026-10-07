"""Input parsing and normalization."""

import csv
import json
from pathlib import Path
from typing import Any


FIELDS = [
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "process",
    "command_line",
    "status",
    "message",
]


def normalize_event(event: dict[str, Any]) -> dict[str, str]:
    """Return a normalized event with predictable string fields."""
    normalized = {}
    for field in FIELDS:
        value = event.get(field, "")
        normalized[field] = "" if value is None else str(value).strip()
    return normalized


def load_logs(path: str, file_format: str = "auto") -> list[dict[str, str]]:
    """Load CSV or JSON logs and normalize their fields."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    fmt = file_format.lower()
    if fmt == "auto":
        fmt = file_path.suffix.lower().lstrip(".")

    if fmt == "csv":
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [normalize_event(row) for row in csv.DictReader(handle)]

    if fmt == "json":
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if not isinstance(data, list):
            raise ValueError("JSON input must contain an array of log events.")

        return [normalize_event(item) for item in data]

    raise ValueError("Unsupported format. Use csv, json, or auto.")

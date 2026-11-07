"""Parse JSONL, a JSON array, or CSV into events.

The upload is data, never a path and never a command. Callers enforce
the size cap before calling this module.
"""

import csv
import io
import json
from datetime import datetime, timezone

from app.models import Event

MAX_EVENTS = 5000

_ALIASES = {
    "ts": "timestamp",
    "time": "timestamp",
    "datetime": "timestamp",
    "action": "event_type",
    "type": "event_type",
    "username": "user",
    "src": "src_ip",
    "dst_ip": "dest_ip",
    "dst_host": "dest_host",
    "message": "detail",
    "bytes": "byte_count",
    "size_bytes": "byte_count",
}


class ParseError(ValueError):
    """The file is not a log we can read."""


def parse_logs(text: str) -> list[Event]:
    stripped = text.lstrip("\ufeff").strip()
    if not stripped:
        raise ParseError("The file is empty.")
    if stripped[0] in "{[":
        events = _parse_jsonish(stripped)
    else:
        events = _parse_csv(stripped)
    if len(events) > MAX_EVENTS:
        raise ParseError(f"Too many events. The limit is {MAX_EVENTS}.")
    seen: set[str] = set()
    for event in events:
        if event.id in seen:
            raise ParseError(f"Duplicate event id {event.id}.")
        seen.add(event.id)
    events.sort(key=lambda event: (event.timestamp, event.id))
    return events


def _parse_jsonish(text: str) -> list[Event]:
    if text[0] == "[":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError("The JSON array could not be parsed.") from exc
        if not isinstance(payload, list):
            raise ParseError("Expected a JSON array of events.")
        records = []
        for index, item in enumerate(payload, start=1):
            if not isinstance(item, dict):
                raise ParseError(f"Event {index} is not an object.")
            records.append(item)
        return [_event_from_mapping(record, index) for index, record in enumerate(records, start=1)]

    events: list[Event] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Line {line_number} is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ParseError(f"Line {line_number} is not an object.")
        event = _event_from_mapping(payload, line_number)
        if event.id in seen:
            raise ParseError(f"Duplicate event id {event.id}.")
        seen.add(event.id)
        events.append(event)
    if not events:
        raise ParseError("No events found.")
    return events


def _parse_csv(text: str) -> list[Event]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ParseError("The CSV file needs a header row.")
    events: list[Event] = []
    seen: set[str] = set()
    for line_number, row in enumerate(reader, start=2):
        if row is None or not any((value or "").strip() for value in row.values()):
            continue
        event = _event_from_mapping(dict(row), line_number)
        if event.id in seen:
            raise ParseError(f"Duplicate event id {event.id}.")
        seen.add(event.id)
        events.append(event)
    if not events:
        raise ParseError("No events found.")
    return events


def _event_from_mapping(raw: dict, line_number: int) -> Event:
    mapped: dict[str, object] = {}
    for key, value in raw.items():
        if key is None:
            continue
        name = _ALIASES.get(str(key).strip(), str(key).strip())
        if isinstance(value, str):
            value = value.strip()
            if value == "":
                value = None
        mapped[name] = value

    missing = [field for field in ("timestamp", "host", "event_type") if not mapped.get(field)]
    if missing:
        joined = ", ".join(missing)
        raise ParseError(f"Line {line_number} is missing {joined}.")

    timestamp = mapped["timestamp"]
    if not isinstance(timestamp, str):
        raise ParseError(f"Line {line_number} has a timestamp that is not text.")
    try:
        parsed_time = _parse_timestamp(timestamp)
    except ValueError as exc:
        raise ParseError(f"Line {line_number} has an unreadable timestamp.") from exc

    byte_count = mapped.get("byte_count")
    parsed_bytes: int | None = None
    if byte_count not in (None, ""):
        try:
            parsed_bytes = int(byte_count)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ParseError(f"Line {line_number} has a byte count that is not an integer.") from exc
        if parsed_bytes < 0:
            raise ParseError(f"Line {line_number} has a negative byte count.")

    event_id = mapped.get("id")
    if not isinstance(event_id, str) or not event_id:
        event_id = f"evt-{line_number}"

    result = mapped.get("result") or "success"
    if not isinstance(result, str):
        result = "success"

    def text(name: str) -> str | None:
        value = mapped.get(name)
        if value is None:
            return None
        return str(value)

    host = text("host")
    event_type = text("event_type")
    if not host or not event_type:
        raise ParseError(f"Line {line_number} is missing host or event_type.")

    return Event(
        id=event_id,
        timestamp=parsed_time,
        host=host,
        source=text("source") or "unknown",
        event_type=event_type,
        user=text("user"),
        src_ip=text("src_ip"),
        src_host=text("src_host"),
        dest_ip=text("dest_ip"),
        dest_host=text("dest_host"),
        result=_normalize_result(result),
        detail=text("detail") or "",
        byte_count=parsed_bytes,
    )


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_result(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"fail", "failed", "failure", "denied", "deny"}:
        return "failure"
    if lowered in {"ok", "success", "succeeded", "allow", "allowed"}:
        return "success"
    return lowered

"""Bundled demonstration logs. These are fictional and use documentation addresses."""

from pathlib import Path

from app.models import CaseInfo, Event, SampleSummary
from app.parser import parse_logs

DATA_DIR = Path(__file__).parent / "data"

SAMPLES: dict[str, dict[str, str]] = {
    "northwind": {
        "title": "Northwind Logistics",
        "subtitle": "Simulated overnight activity",
        "note": "Fictional company. Addresses are TEST-NET documentation ranges, not live hosts.",
        "file": "northwind.jsonl",
    },
    "benign": {
        "title": "Quiet office day",
        "subtitle": "Ordinary logons and a backup job",
        "note": "A control file. The rules should not build an attack path from it.",
        "file": "benign.jsonl",
    },
}


def list_samples() -> list[SampleSummary]:
    summaries = []
    for sample_id in SAMPLES:
        case, events = load_sample(sample_id)
        summaries.append(
            SampleSummary(
                id=case.id,
                title=case.title,
                subtitle=case.subtitle,
                note=case.note,
                event_count=len(events),
            )
        )
    return summaries


def load_sample(sample_id: str) -> tuple[CaseInfo, list[Event]]:
    spec = SAMPLES.get(sample_id)
    if spec is None:
        raise KeyError(sample_id)
    text = (DATA_DIR / spec["file"]).read_text(encoding="utf-8")
    events = parse_logs(text)
    case = CaseInfo(
        id=sample_id,
        title=spec["title"],
        subtitle=spec["subtitle"],
        note=spec["note"],
        origin="sample",
    )
    return case, events


def sample_log_path(sample_id: str) -> Path:
    spec = SAMPLES.get(sample_id)
    if spec is None:
        raise KeyError(sample_id)
    return DATA_DIR / spec["file"]

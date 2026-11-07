"""The Northwind case is the contract for the demo story."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.grok_bot import investigate_sample
from app.grok_client import GrokError, summary_is_usable
from app.parser import ParseError, parse_logs

BANNED = ("mimikatz", "shellcode", "meterpreter", "powershell -enc", "psexec")
EXPECTED_FINDINGS = [
    "access-a-chen-203-0-113-44",
    "privilege-wkst-14-administrators",
    "service-wkst-14-remotesupporthelper",
    "lateral-wkst-14-file-02-1",
    "collection-1",
    "lateral-wkst-14-dc-01-1",
    "privilege-dc-01-it-admins",
    "transfer-1",
]


@pytest.fixture(autouse=True)
def no_grok_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XAI_API_KEY", raising=False)


@pytest.fixture
def client() -> TestClient:
    from app.main import app

    return TestClient(app)


def test_northwind_story() -> None:
    investigation = investigate_sample("northwind")
    assert [finding.id for finding in investigation.findings] == EXPECTED_FINDINGS
    assert investigation.report.risk == "high"
    assert investigation.report.summary.count("lateral movement") == 1
    assert investigation.report.reasoning_source == "local-evidence-reasoner"
    assert investigation.stats.event_count == 26
    assert investigation.stats.evidence_count == 21
    assert set(investigation.report.rules_silent) == set()
    assert [step.id for step in investigation.workflow] == ["ingest", "detect", "correlate", "reason", "report"]
    assert all(step.owner == "grok-bot" for step in investigation.workflow)


def test_every_citation_is_a_real_event() -> None:
    investigation = investigate_sample("northwind")
    known = {event.id for event in investigation.events}
    for finding in investigation.findings:
        assert finding.evidence_ids
        assert set(finding.evidence_ids) <= known
    for conclusion in investigation.report.conclusions:
        assert conclusion.evidence_ids
        assert set(conclusion.evidence_ids) <= known
    for action in investigation.report.recommendations:
        assert set(action.evidence_ids) <= known
    covered = {event_id for edge in investigation.graph.edges for event_id in edge.evidence_ids}
    cited = {event_id for finding in investigation.findings for event_id in finding.evidence_ids}
    assert cited <= covered
    for edge in investigation.graph.edges:
        assert edge.evidence_ids
        assert set(edge.evidence_ids) <= known


def test_context_events_stay_off_the_path() -> None:
    investigation = investigate_sample("northwind")
    cited = {event_id for finding in investigation.findings for event_id in finding.evidence_ids}
    assert {"e01", "e02", "e03", "e04", "e26"}.isdisjoint(cited)
    labels = {node.label for node in investigation.graph.nodes}
    assert "BACKUP-01" not in labels
    assert "WKST-02" not in labels
    assert "WKST-14" in labels
    assert "DC-01" in labels


def test_graph_reads_left_to_right() -> None:
    investigation = investigate_sample("northwind")
    ranks = {node.id: node.rank for node in investigation.graph.nodes}
    assert ranks["ip:203.0.113.44"] < ranks["user:a.chen"] < ranks["host:WKST-14"] < ranks["host:DC-01"]
    assert ranks["ip:198.51.100.23"] == max(ranks.values())


def test_hypotheses_are_separate_from_observations() -> None:
    investigation = investigate_sample("northwind")
    kinds = {item.kind for item in investigation.report.conclusions}
    assert kinds == {"observed", "hypothesis"}
    blob = " ".join(
        item.statement for item in investigation.report.conclusions if item.kind == "hypothesis"
    ).lower()
    assert "hypothesis" not in blob or "consistent" in blob
    assert "secret" in blob
    for action in investigation.report.recommendations:
        lowered = f"{action.title} {action.detail}".lower()
        for banned in BANNED:
            assert banned not in lowered


def test_isolation_targets_the_workstation() -> None:
    investigation = investigate_sample("northwind")
    isolate = next(item for item in investigation.report.recommendations if item.title.startswith("Isolate"))
    assert "WKST-14" in isolate.detail
    assert "DC-01" not in isolate.detail
    titles = [item.title for item in investigation.report.recommendations]
    assert "Review IT-Admins on DC-01" in titles
    assert "Block 203.0.113.44" in titles
    assert any(title.startswith("Reset svc-backup") for title in titles)


def test_benign_day_is_quiet() -> None:
    investigation = investigate_sample("benign")
    assert investigation.findings == []
    assert investigation.graph.nodes == []
    assert investigation.report.risk == "low"
    assert "b07" in {event.id for event in investigation.events}


def test_finance_access_without_prior_suspicion_is_quiet() -> None:
    events = parse_logs(
        '{"id":"n1","timestamp":"2026-03-18T15:00:00Z","host":"FILE-02","event_type":"share.access",'
        '"user":"m.ross","src_ip":"10.0.4.15","result":"success",'
        '"detail":"Read \\\\\\\\FILE-02\\\\finance\\\\budget.xlsx"}\n'
    )
    from app.detect import detect
    from app.network import is_internal

    assert "finance" in events[0].detail
    assert detect(events) == []
    assert is_internal("10.8.0.22")
    assert not is_internal("203.0.113.44")
    assert not is_internal("198.51.100.23")


def test_parser_rejects_bad_input() -> None:
    with pytest.raises(ParseError):
        parse_logs("not,a,valid\n1,2,3\n")
    with pytest.raises(ParseError):
        parse_logs('{"id":"a","timestamp":"2026-03-18T15:00:00Z","host":"H"}\n')
    with pytest.raises(ParseError):
        parse_logs(
            '{"id":"a","timestamp":"2026-03-18T15:00:00Z","host":"H","event_type":"auth.logon"}\n'
            '{"id":"a","timestamp":"2026-03-18T15:01:00Z","host":"H","event_type":"auth.logon"}\n'
        )


def test_csv_upload_and_limits(client: TestClient) -> None:
    csv_text = (
        "timestamp,host,event_type,user,src_ip,result,detail\n"
        "2026-03-18T15:00:00Z,WKST-02,auth.logon.interactive,m.ross,10.0.4.15,success,Office logon\n"
    )
    response = client.post(
        "/api/investigate",
        files={"file": ("day.csv", csv_text.encode(), "text/csv")},
    )
    assert response.status_code == 200
    assert response.json()["findings"] == []

    rejected = client.post(
        "/api/investigate",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert rejected.status_code == 400

    oversized = client.post(
        "/api/investigate",
        files={"file": ("big.jsonl", b"{" * 2_000_001, "application/json")},
    )
    assert oversized.status_code == 413


def test_upload_matches_sample_findings(client: TestClient) -> None:
    sample = client.get("/api/samples/northwind/investigation")
    assert sample.status_code == 200
    raw = Path("app/data/northwind.jsonl").read_bytes()
    uploaded = client.post(
        "/api/investigate",
        files={"file": ("northwind.jsonl", raw, "application/json")},
    )
    assert uploaded.status_code == 200
    assert [item["id"] for item in uploaded.json()["findings"]] == [item["id"] for item in sample.json()["findings"]]
    missing = client.get("/api/samples/missing/investigation")
    assert missing.status_code == 404
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["grok_configured"] is False


def test_grok_summary_guard() -> None:
    allowed = {"e13", "e25"}
    assert summary_is_usable("The session in e13 is the start of the timeline, and e25 records the transfer.", allowed)
    assert not summary_is_usable("See e99 for the payload steps.", allowed)
    assert not summary_is_usable("Use mimikatz as described in e13.", allowed)
    assert not summary_is_usable("short", allowed)


def test_grok_rejection_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(summary: str, allowed: set[str]) -> str:
        raise GrokError("discard")

    monkeypatch.setattr("app.grok_bot.grok_client.rewrite_summary", explode)
    investigation = investigate_sample("northwind", allow_grok=True)
    assert investigation.report.reasoning_source == "local-evidence-reasoner"
    assert "discarded" in investigation.report.reasoning_note
    assert "e05" in investigation.report.summary


def test_grok_rewrite_is_used_when_it_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    def rewrite(summary: str, allowed: set[str]) -> str:
        return summary + " Rewritten around " + sorted(allowed)[0] + "."

    monkeypatch.setattr("app.grok_bot.grok_client.rewrite_summary", rewrite)
    investigation = investigate_sample("northwind", allow_grok=True)
    assert investigation.report.reasoning_source == "grok"
    assert "Rewritten around" in investigation.report.summary
    assert investigation.report.conclusions[0].kind == "observed"

# SENTINEL

SENTINEL is an investigation workbench. It reads a security log, highlights the events that match a small set of rules, draws the path those events support, and writes a report where every conclusion cites a log line.

The Northwind Logistics case is fictional. It is the 90-second demo: repeated VPN failures, a privileged group change, movement from a workstation to a file server and a domain controller, and a large outbound transfer. Ordinary activity in the same file, including a backup job, stays off the path.

## Demo

1. Start the API and the web app (below).
2. Open the UI and choose **Investigate Northwind**.
3. Grok Bot runs five steps: ingest, detect, correlate, reason, report.
4. Select a finding. The graph and the evidence panel move to the events that finding cites.
5. Click a host or an edge to read the same events from the path.
6. Read the ledger. Observed rows restate the logs. Yellow rows are hypotheses, including where the logs stop.
7. The actions are containment and recovery: block the source address, disable the account, isolate the workstation, review the group changes.

**Quiet office day** is the control. A single external failure, office logons, and a backup do not build a path.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173.

Docker serves the built UI and the API on one port:

```bash
docker compose up --build
```

Open http://127.0.0.1:8000.

## Grok Bot

The investigation is one workflow owned by Grok Bot:

| Step | What it does |
| --- | --- |
| Ingest | Parse JSONL, a JSON array, or CSV. |
| Detect | Apply the rules below. |
| Correlate | Build a graph whose edges cite events. |
| Reason | Rewrite the summary with Grok when `XAI_API_KEY` is set. Otherwise keep the local summary. |
| Report | Ledger, risk, and defensive actions. |

The ledger, the graph, and the actions always come from the rules. Grok is only allowed to rewrite the summary. A draft is discarded if it cites an event id that is not in the file, or if it includes attack procedure.

Set the key on the API process. Do not commit it.

```bash
XAI_API_KEY=... uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Optional: `SENTINEL_GROK_MODEL` (default `grok-4.7`). The `xai-quickstart/` folder is the small Node example of the same API.

## Rules

Business hours are 08:00–18:00 UTC. An address is internal only when it is RFC 1918, loopback, or link-local. TEST-NET documentation ranges count as external.

- **repeated-auth** — five or more failures for the same account and source, then a success.
- **offhours-external-auth** — a successful authentication from outside the private network, outside business hours.
- **privileged-group-change** — an account added to an administrator group.
- **new-service** — a service installed on a host already on the path.
- **lateral-logon** — a network logon whose source host is already on the path.
- **sensitive-access** — finance, payroll, or similarly marked paths, from an account or host already on the path.
- **large-outbound-transfer** — more than 100 MB to an external address.

A quiet finance read by an unrelated account does not fire. The backup job in the sample does not fire.

## Log format

JSONL (one object per line), a JSON array, or CSV. Required fields: `timestamp`, `host`, `event_type`. Useful fields: `id`, `user`, `src_ip`, `src_host`, `dest_ip`, `dest_host`, `result`, `detail`, `byte_count`.

```json
{"id":"e13","timestamp":"2026-03-18T01:19:02Z","host":"vpn-gw-01","event_type":"auth.logon.vpn","user":"a.chen","src_ip":"203.0.113.44","dest_host":"WKST-14","result":"success","detail":"VPN session established"}
```

Uploads are limited to 2 MB and 5,000 events. The sample files are `backend/app/data/northwind.jsonl` and `backend/app/data/benign.jsonl`.

## API

- `GET /api/health`
- `GET /api/samples`
- `GET /api/samples/{id}/investigation`
- `GET /api/samples/{id}/logs`
- `POST /api/investigate` with a multipart field named `file`

## Tests

```bash
cd backend && python3 -m pytest
cd frontend && npm run typecheck
```

## What this does not do

SENTINEL does not scan networks, validate vulnerabilities by exploiting them, or collect telemetry. A finding exists only when a parsed event supports it. Extending it with live monitoring or an isolated lab check is future work, and that lab check would still have to be authorized and separate from this report.

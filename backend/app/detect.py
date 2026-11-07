"""Rule detection over parsed logs.

A rule fires only from fields in the events. It does not scan hosts,
guess exploits, or invent activity that is absent from the file.
"""

import re
from datetime import datetime, timedelta, timezone

from app.models import Event, Finding
from app.network import is_internal

BUSINESS_START = 8
BUSINESS_END = 18
BUSINESS_LABEL = "08:00–18:00 UTC"
FAILURE_GAP = timedelta(minutes=10)
SUCCESS_WINDOW = timedelta(minutes=15)
SESSION_WINDOW = timedelta(minutes=30)
MERGE_WINDOW = timedelta(hours=6)
BRUTE_FORCE_MIN = 5
TRANSFER_MIN_BYTES = 100_000_000

ADMIN_GROUPS = {
    "administrators",
    "domain admins",
    "it-admins",
    "enterprise admins",
    "schema admins",
}
SENSITIVE_MARKERS = ("finance", "payroll", "hr-confidential", "customer-secrets")
DIRECT_AUTH = {"auth.logon", "auth.logon.vpn", "auth.logon.interactive"}
LATERAL_AUTH = {"auth.logon.network", "auth.logon.remote"}
COLLECTION_TYPES = {"share.access", "file.access", "file.staged"}

GROUP_RE = re.compile(
    r"([A-Za-z0-9._-]+) added to group ([A-Za-z0-9][A-Za-z0-9 _-]*)",
    re.IGNORECASE,
)
BYTE_RE = re.compile(r"(?:bytes|size_bytes)=(\d+)")

RULES = [
    "repeated-auth",
    "offhours-external-auth",
    "privileged-group-change",
    "new-service",
    "lateral-logon",
    "sensitive-access",
    "large-outbound-transfer",
]


def detect(events: list[Event]) -> list[Finding]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    findings: list[Finding] = []
    implicated_users: set[str] = set()
    implicated_hosts: set[str] = set()

    findings.extend(_initial_access(ordered))
    _implicate_from(findings, ordered, implicated_users, implicated_hosts)

    findings.extend(_privilege(ordered, implicated_users, implicated_hosts))
    _implicate_from(findings, ordered, implicated_users, implicated_hosts)

    findings.extend(_services(ordered, implicated_users, implicated_hosts))
    findings.extend(_lateral(ordered, implicated_hosts))
    _implicate_from(findings, ordered, implicated_users, implicated_hosts)
    findings.extend(_collection(ordered, implicated_users, implicated_hosts))
    findings.extend(_transfers(ordered, implicated_users, implicated_hosts))

    findings.sort(key=lambda finding: (_first_time(finding, ordered), finding.id))
    return findings


def _initial_access(events: list[Event]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[Event]] = {}
    for event in events:
        if event.event_type not in DIRECT_AUTH or not event.user or not event.src_ip:
            continue
        grouped.setdefault((event.user, event.src_ip), []).append(event)

    findings: list[Finding] = []
    consumed: set[str] = set()
    for (user, src_ip), related in grouped.items():
        related.sort(key=lambda event: event.timestamp)
        failures = [event for event in related if event.result == "failure"]
        successes = [event for event in related if event.result == "success" and event.id not in consumed]
        for success in successes:
            cluster = _cluster_before(failures, success.timestamp)
            external = not is_internal(src_ip)
            off_hours = _off_hours(success.timestamp)
            rules: list[str] = []
            if len(cluster) >= BRUTE_FORCE_MIN:
                rules.append("repeated-auth")
            if external and off_hours:
                rules.append("offhours-external-auth")
            if not rules:
                continue
            evidence = [*cluster, success]
            follow = _session_followup(events, success)
            for event in follow:
                if event.id not in {item.id for item in evidence}:
                    evidence.append(event)
            consumed.add(success.id)
            findings.append(_access_finding(user, src_ip, evidence, rules))
    return findings


def _access_finding(user: str, src_ip: str, evidence: list[Event], rules: list[str]) -> Finding:
    evidence = sorted(evidence, key=lambda event: event.timestamp)
    failures = [event for event in evidence if event.result == "failure"]
    success = next(event for event in evidence if event.result == "success" and event.event_type in DIRECT_AUTH)
    interactive = [
        event
        for event in evidence
        if event.event_type == "auth.logon.interactive" and event.host != success.host
    ]
    parts = []
    if failures:
        parts.append(
            f"{user} recorded {len(failures)} failed authentications from {src_ip} "
            f"between {_clock(failures[0].timestamp)} and {_clock(failures[-1].timestamp)} "
            f"({_cite(failures)})."
        )
    parts.append(
        f"A successful { _auth_name(success.event_type) } followed at {_clock(success.timestamp)} "
        f"on {success.host} ({success.id})."
    )
    if interactive:
        landed = interactive[0]
        parts.append(
            f"An interactive session then started on {landed.host} at {_clock(landed.timestamp)} ({landed.id})."
        )
    if "offhours-external-auth" in rules:
        parts.append(
            f"{src_ip} is outside the private network, and the success sits outside {BUSINESS_LABEL}."
        )
    elif not is_internal(src_ip):
        parts.append(f"{src_ip} is outside the private network.")

    entities = {"user": user, "src_ip": src_ip, "host": success.host}
    if success.dest_host:
        entities["dest_host"] = success.dest_host
    if interactive:
        entities["workstation"] = interactive[0].host

    severity = "high" if "offhours-external-auth" in rules or "repeated-auth" in rules else "medium"
    title = "Authentication succeeded after repeated failures" if failures else "Off-hours external authentication"
    return Finding(
        id=f"access-{_slug(user)}-{_slug(src_ip)}",
        title=title,
        category="initial_access",
        severity=severity,  # type: ignore[arg-type]
        summary=" ".join(parts),
        evidence_ids=[event.id for event in evidence],
        rule_ids=rules,
        entities=entities,
    )


def _privilege(events: list[Event], users: set[str], hosts: set[str]) -> list[Finding]:
    changes = []
    for event in events:
        if event.event_type not in {"account.group_add", "account.privilege_assigned"}:
            continue
        parsed = _parse_group(event)
        if event.event_type == "account.group_add" and not parsed:
            continue
        if event.event_type == "account.group_add" and parsed and not _adminish(parsed[1]):
            continue
        if event.event_type == "account.privilege_assigned" and not _touches(event, users, hosts):
            near_group = any(
                other.event_type == "account.group_add"
                and other.host == event.host
                and abs(other.timestamp - event.timestamp) <= timedelta(minutes=10)
                for other in events
            )
            if not near_group and not _touches(event, users, hosts):
                continue
        changes.append(event)

    findings: list[Finding] = []
    used: set[str] = set()
    for event in changes:
        if event.id in used or event.event_type != "account.group_add":
            continue
        companion = [
            other
            for other in changes
            if other.event_type == "account.privilege_assigned"
            and other.host == event.host
            and other.id not in used
            and abs(other.timestamp - event.timestamp) <= timedelta(minutes=10)
        ]
        bundle = [event, *companion]
        for item in bundle:
            used.add(item.id)
        subject, group = _parse_group(event) or (event.user or "an account", "a privileged group")
        actor = event.user or "an account"
        where = event.src_host or event.host
        origin = f" The change was recorded from {event.src_host}." if event.src_host and event.src_host != event.host else ""
        privilege_bits = ""
        if companion:
            privilege_bits = (
                f" Special privileges were assigned at {_clock(companion[0].timestamp)} ({_cite(companion)})."
            )
        summary = (
            f"At {_clock(event.timestamp)} on {event.host}, {actor} added {subject} to {group.strip()} "
            f"({event.id}).{origin}{privilege_bits}"
        )
        high = _touches(event, users, hosts) or any(_touches(item, users, hosts) for item in companion)
        findings.append(
            Finding(
                id=f"privilege-{_slug(event.host)}-{_slug(group)}",
                title=f"Privileged group change on {event.host}",
                category="privilege",
                severity="high" if high else "medium",
                summary=summary,
                evidence_ids=[item.id for item in bundle],
                rule_ids=["privileged-group-change"],
                entities={
                    "host": event.host,
                    "actor": actor,
                    "subject": subject,
                    "group": group.strip(),
                    **({"src_host": event.src_host} if event.src_host else {}),
                },
            )
        )
    return findings


def _services(events: list[Event], users: set[str], hosts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.event_type != "service.installed":
            continue
        if not _touches(event, users, hosts):
            continue
        name = _service_name(event.detail)
        findings.append(
            Finding(
                id=f"service-{_slug(event.host)}-{_slug(name)}",
                title=f"New service installed on {event.host}",
                category="persistence",
                severity="medium",
                summary=(
                    f"At {_clock(event.timestamp)} a service named {name} was installed on {event.host} "
                    f"by {event.user or 'an unnamed account'} ({event.id}). "
                    "The log records the installation. It does not say what the service runs."
                ),
                evidence_ids=[event.id],
                rule_ids=["new-service"],
                entities={"host": event.host, "service": name, **({"user": event.user} if event.user else {})},
            )
        )
    return findings


def _lateral(events: list[Event], hosts: set[str]) -> list[Finding]:
    candidates = []
    for event in events:
        if event.event_type not in LATERAL_AUTH:
            continue
        source = event.src_host
        dest = event.dest_host or event.host
        if not source or not dest or source == dest:
            continue
        if source not in hosts:
            continue
        candidates.append(event)

    buckets: dict[tuple[str, str], list[Event]] = {}
    for event in candidates:
        source = event.src_host or ""
        dest = event.dest_host or event.host
        buckets.setdefault((source, dest), []).append(event)

    findings: list[Finding] = []
    for (source, dest), related in buckets.items():
        related.sort(key=lambda event: event.timestamp)
        chunks = _chunk(related, timedelta(minutes=45))
        for index, chunk in enumerate(chunks, start=1):
            users = _unique(event.user for event in chunk if event.user)
            denied = [event for event in chunk if event.result == "failure"]
            allowed = [event for event in chunk if event.result == "success"]
            sentences = []
            for event in chunk:
                outcome = "was denied" if event.result == "failure" else "succeeded"
                sentences.append(
                    f"At {_clock(event.timestamp)} a network logon from {source} to {dest} "
                    f"as {event.user or 'an unnamed account'} {outcome} ({event.id})."
                )
            if denied and allowed:
                title = f"Logons from {source} to {dest}"
            elif allowed:
                title = f"Network logon from {source} to {dest}"
            else:
                title = f"Denied logon from {source} to {dest}"
            findings.append(
                Finding(
                    id=f"lateral-{_slug(source)}-{_slug(dest)}-{index}",
                    title=title,
                    category="lateral_movement",
                    severity="high" if allowed else "medium",
                    summary=" ".join(sentences),
                    evidence_ids=[event.id for event in chunk],
                    rule_ids=["lateral-logon"],
                    entities={"src_host": source, "dest_host": dest, "users": ", ".join(users)},
                )
            )
    return findings


def _collection(events: list[Event], users: set[str], hosts: set[str]) -> list[Finding]:
    hits = []
    for event in events:
        if event.event_type not in COLLECTION_TYPES:
            continue
        if not _sensitive(event.detail):
            continue
        if not _touches(event, users, hosts):
            continue
        hits.append(event)
    findings: list[Finding] = []
    for index, chunk in enumerate(_chunk(hits, MERGE_WINDOW), start=1):
        staged = [event for event in chunk if event.event_type == "file.staged" or _byte_count(event)]
        reads = [event for event in chunk if event not in staged]
        names = _unique(event.user for event in chunk if event.user)
        places = _unique(event.host for event in chunk)
        size_bits = ""
        if staged:
            total = sum(_byte_count(event) for event in staged)
            if total:
                size_bits = f" Staged data in this set totals {_human_bytes(total)}."
        summary = (
            f"{', '.join(names) or 'An account'} accessed sensitive paths on {', '.join(places)} "
            f"({_cite(chunk)}).{size_bits} "
            "The paths match the finance and payroll markers used by this rule."
        )
        findings.append(
            Finding(
                id=f"collection-{index}",
                title="Sensitive data accessed",
                category="collection",
                severity="high",
                summary=summary,
                evidence_ids=[event.id for event in chunk],
                rule_ids=["sensitive-access"],
                entities={"users": ", ".join(names), "hosts": ", ".join(places)},
            )
        )
    return findings


def _transfers(events: list[Event], users: set[str], hosts: set[str]) -> list[Finding]:
    hits = []
    for event in events:
        if event.event_type != "network.transfer":
            continue
        if not event.dest_ip or is_internal(event.dest_ip):
            continue
        if _byte_count(event) < TRANSFER_MIN_BYTES:
            continue
        hits.append(event)
    findings: list[Finding] = []
    for index, chunk in enumerate(_chunk(hits, MERGE_WINDOW), start=1):
        implicated = any(_touches(event, users, hosts) for event in chunk)
        sentences = []
        for event in chunk:
            sentences.append(
                f"At {_clock(event.timestamp)} {event.host} sent {_human_bytes(_byte_count(event))} "
                f"to {event.dest_ip} ({event.id})."
            )
        sentences.append("The log records the transfer. It does not name the contents or the receiving application.")
        findings.append(
            Finding(
                id=f"transfer-{index}",
                title="Large outbound transfer",
                category="exfiltration",
                severity="high" if implicated else "medium",
                summary=" ".join(sentences),
                evidence_ids=[event.id for event in chunk],
                rule_ids=["large-outbound-transfer"],
                entities={
                    "dest_ip": chunk[-1].dest_ip or "",
                    "host": chunk[-1].host,
                    **({"user": chunk[-1].user} if chunk[-1].user else {}),
                },
            )
        )
    return findings


def _cluster_before(failures: list[Event], moment: datetime) -> list[Event]:
    prior = [event for event in failures if event.timestamp <= moment and moment - event.timestamp <= SUCCESS_WINDOW]
    if not prior:
        # A longer burst can start earlier than the success window if the failures
        # themselves are continuous. Walk backward while gaps stay small.
        prior = [event for event in failures if event.timestamp <= moment]
    if not prior:
        return []
    prior.sort(key=lambda event: event.timestamp)
    # Keep the trailing run whose last event is inside the success window.
    if moment - prior[-1].timestamp > SUCCESS_WINDOW:
        return []
    cluster = [prior[-1]]
    for event in reversed(prior[:-1]):
        if cluster[0].timestamp - event.timestamp <= FAILURE_GAP:
            cluster.insert(0, event)
        else:
            break
    return cluster


def _session_followup(events: list[Event], success: Event) -> list[Event]:
    if not success.user:
        return []
    target = success.dest_host
    follow = []
    for event in events:
        if event.id == success.id or event.user != success.user:
            continue
        if event.event_type != "auth.logon.interactive" or event.result != "success":
            continue
        if event.timestamp < success.timestamp or event.timestamp - success.timestamp > SESSION_WINDOW:
            continue
        if target and event.host != target:
            continue
        follow.append(event)
    return follow


def _implicate_from(
    findings: list[Finding],
    events: list[Event],
    users: set[str],
    hosts: set[str],
) -> None:
    by_id = {event.id: event for event in events}
    for finding in findings:
        for key in ("user", "actor", "subject"):
            value = finding.entities.get(key)
            if value:
                users.add(value)
        for key in ("host", "src_host", "dest_host", "workstation"):
            value = finding.entities.get(key)
            if value:
                hosts.add(value)
        for event_id in finding.evidence_ids:
            event = by_id.get(event_id)
            if event is None:
                continue
            if event.user:
                users.add(event.user)
            hosts.add(event.host)
            if event.src_host:
                hosts.add(event.src_host)
            if event.dest_host:
                hosts.add(event.dest_host)


def _touches(event: Event, users: set[str], hosts: set[str]) -> bool:
    if event.user and event.user in users:
        return True
    return any(place in hosts for place in (event.host, event.src_host, event.dest_host) if place)


def _parse_group(event: Event) -> tuple[str, str] | None:
    match = GROUP_RE.search(event.detail)
    if not match:
        return None
    return match.group(1), match.group(2).strip()


def _adminish(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in ADMIN_GROUPS or "admin" in lowered


def _service_name(detail: str) -> str:
    match = re.search(r"[Ss]ervice ([A-Za-z0-9._-]+)", detail)
    return match.group(1) if match else "unnamed"


def _sensitive(detail: str) -> bool:
    lowered = detail.lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _byte_count(event: Event) -> int:
    if event.byte_count:
        return event.byte_count
    match = BYTE_RE.search(event.detail)
    return int(match.group(1)) if match else 0


def _off_hours(moment: datetime) -> bool:
    hour = moment.astimezone(timezone.utc).hour
    return hour < BUSINESS_START or hour >= BUSINESS_END


def _chunk(events: list[Event], gap: timedelta) -> list[list[Event]]:
    if not events:
        return []
    ordered = sorted(events, key=lambda event: event.timestamp)
    chunks: list[list[Event]] = [[ordered[0]]]
    for event in ordered[1:]:
        if event.timestamp - chunks[-1][-1].timestamp <= gap:
            chunks[-1].append(event)
        else:
            chunks.append([event])
    return chunks


def _first_time(finding: Finding, events: list[Event]) -> datetime:
    by_id = {event.id: event.timestamp for event in events}
    times = [by_id[event_id] for event_id in finding.evidence_ids if event_id in by_id]
    if not times:
        return datetime.max.replace(tzinfo=timezone.utc)
    return min(times)


def _clock(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%H:%M:%S UTC")


def _cite(events: list[Event]) -> str:
    return ", ".join(event.id for event in events)


def _auth_name(event_type: str) -> str:
    names = {
        "auth.logon.vpn": "VPN authentication",
        "auth.logon.interactive": "interactive logon",
        "auth.logon": "authentication",
    }
    return names.get(event_type, "authentication")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "unknown"


def _unique(values) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return seen


def _human_bytes(count: int) -> str:
    if count >= 1_000_000_000:
        return f"{count / 1_000_000_000:.1f} GB"
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f} MB"
    if count >= 1_000:
        return f"{count / 1_000:.1f} KB"
    return f"{count} B"

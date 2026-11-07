"""Turn findings into an evidence ledger and defensive recommendations."""

from app.detect import RULES, _human_bytes
from app.models import Conclusion, Event, Finding, Recommendation, Report


def build_report(
    events: list[Event],
    findings: list[Finding],
    *,
    title: str,
    summary: str | None = None,
    reasoning_source: str = "local-evidence-reasoner",
    reasoning_note: str,
) -> Report:
    by_id = {event.id: event for event in events}
    conclusions = _conclusions(findings, by_id)
    recommendations = _recommendations(findings)
    fired = [rule for rule in RULES if any(rule in finding.rule_ids for finding in findings)]
    silent = [rule for rule in RULES if rule not in fired]
    risk, rationale = _risk(findings)
    root = _root_cause(findings)
    lead = summary or _local_summary(events, findings)
    return Report(
        title=title,
        summary=lead,
        risk=risk,  # type: ignore[arg-type]
        risk_rationale=rationale,
        root_cause=root,
        conclusions=conclusions,
        recommendations=recommendations,
        rules_fired=fired,
        rules_silent=silent,
        reasoning_source=reasoning_source,  # type: ignore[arg-type]
        reasoning_note=reasoning_note,
    )


def local_summary(events: list[Event], findings: list[Finding]) -> str:
    return _local_summary(events, findings)


def _local_summary(events: list[Event], findings: list[Finding]) -> str:
    if not findings:
        return (
            f"SENTINEL parsed {len(events)} events. None of the detection rules fired. "
            "Office activity in the file, including ordinary logons and backup jobs, was left off the attack path. "
            "That is not a proof that the network is safe. It means this rule set found nothing to explain."
        )
    cited = len({event_id for finding in findings for event_id in finding.evidence_ids})
    seen_categories: list[str] = []
    for finding in findings:
        if finding.category not in seen_categories:
            seen_categories.append(finding.category)
    stage_text = ", ".join(category.replace("_", " ") for category in seen_categories)
    first_id = findings[0].evidence_ids[0]
    last_id = findings[-1].evidence_ids[-1]
    return (
        f"SENTINEL parsed {len(events)} events and cited {cited} of them across {len(findings)} findings, "
        f"from {first_id} to {last_id}. "
        f"The path runs through {stage_text}."
    )


def _conclusions(findings: list[Finding], by_id: dict[str, Event]) -> list[Conclusion]:
    conclusions = [
        Conclusion(statement=finding.summary, evidence_ids=list(finding.evidence_ids), kind="observed")
        for finding in findings
    ]
    conclusions.extend(_hypotheses(findings, by_id))
    return conclusions


def _hypotheses(findings: list[Finding], by_id: dict[str, Event]) -> list[Conclusion]:
    extra: list[Conclusion] = []
    access = next((finding for finding in findings if "repeated-auth" in finding.rule_ids), None)
    if access:
        extra.append(
            Conclusion(
                statement=(
                    "The failed attempts and the later success share an account and a source address. "
                    "That pattern is consistent with guessing or reuse of a secret. "
                    "The logs do not contain the secret, and they do not name a program that produced the attempts."
                ),
                evidence_ids=list(access.evidence_ids),
                kind="hypothesis",
            )
        )
    for finding in findings:
        if finding.category != "lateral_movement":
            continue
        accounts = [part.strip() for part in finding.entities.get("users", "").split(",") if part.strip()]
        if len(accounts) < 2:
            continue
        extra.append(
            Conclusion(
                statement=(
                    f"{finding.entities.get('src_host')} reached {finding.entities.get('dest_host')} "
                    f"as {accounts[0]} and later as {accounts[1]}. "
                    "The dataset does not contain an event that shows how the second account was used on that source host."
                ),
                evidence_ids=list(finding.evidence_ids),
                kind="hypothesis",
            )
        )
    for finding in findings:
        if finding.category != "persistence":
            continue
        extra.append(
            Conclusion(
                statement=(
                    f"The new service on {finding.entities.get('host')} can keep a program running after a reboot. "
                    "That is an inference from the install event. The log does not include the service's behavior."
                ),
                evidence_ids=list(finding.evidence_ids),
                kind="hypothesis",
            )
        )
    staged = [
        by_id[event_id]
        for finding in findings
        if finding.category == "collection"
        for event_id in finding.evidence_ids
        if event_id in by_id and (by_id[event_id].event_type == "file.staged" or (by_id[event_id].byte_count or 0) > 0)
    ]
    transfers = [
        by_id[event_id]
        for finding in findings
        if finding.category == "exfiltration"
        for event_id in finding.evidence_ids
        if event_id in by_id
    ]
    if staged and transfers:
        staged_bytes = sum(event.byte_count or 0 for event in staged)
        sent_bytes = sum(event.byte_count or 0 for event in transfers)
        if staged_bytes and sent_bytes and 0.5 <= sent_bytes / staged_bytes <= 1.5:
            ids = [event.id for event in staged] + [event.id for event in transfers]
            extra.append(
                Conclusion(
                    statement=(
                        f"The outbound transfer ({_human_bytes(sent_bytes)}) is similar in size to the archive "
                        f"recorded earlier ({_human_bytes(staged_bytes)}). "
                        "That is consistent with the archive leaving the network. "
                        "The transfer event does not name a file, so the link stays a hypothesis."
                    ),
                    evidence_ids=ids,
                    kind="hypothesis",
                )
            )
    return extra


def _recommendations(findings: list[Finding]) -> list[Recommendation]:
    if not findings:
        return [
            Recommendation(
                title="No containment action from these rules",
                detail="Keep the log with the ticket if this was a scoped review. The rules did not select an account, host, or address to contain.",
                evidence_ids=[],
            )
        ]
    actions: list[Recommendation] = []
    access = [finding for finding in findings if finding.category == "initial_access"]
    for finding in access:
        src_ip = finding.entities.get("src_ip")
        user = finding.entities.get("user")
        if src_ip:
            actions.append(
                Recommendation(
                    title=f"Block {src_ip}",
                    detail=(
                        f"Block {src_ip} on the VPN gateway and ask the firewall owners to review earlier traffic from that address. "
                        "This contains the source named in the authentication events."
                    ),
                    evidence_ids=list(finding.evidence_ids),
                )
            )
        if user:
            actions.append(
                Recommendation(
                    title=f"Disable {user} until the owner is reached",
                    detail=(
                        f"Disable {user}, contact the person out of band, then set a new secret and require MFA before the account is used again."
                    ),
                    evidence_ids=list(finding.evidence_ids),
                )
            )
    hosts, host_evidence = _workstations(findings)
    if hosts:
        actions.append(
            Recommendation(
                title="Isolate the implicated workstations",
                detail=(
                    f"Remove {', '.join(hosts)} from the network and retain their logs for the investigation. "
                    "Do this through your existing endpoint process."
                ),
                evidence_ids=host_evidence,
            )
        )
    for finding in findings:
        if finding.category != "privilege":
            continue
        subject = finding.entities.get("subject")
        group = finding.entities.get("group")
        host = finding.entities.get("host")
        actions.append(
            Recommendation(
                title=f"Review {group} on {host}",
                detail=(
                    f"Confirm whether {subject} was approved to join {group} on {host}. "
                    "Remove the membership if nobody approved it, and record who still belongs to that group."
                ),
                evidence_ids=list(finding.evidence_ids),
            )
        )
    extra_accounts = []
    extra_ids: list[str] = []
    primary = {finding.entities.get("user") for finding in access}
    for finding in findings:
        if finding.category != "lateral_movement":
            continue
        for account in finding.entities.get("users", "").split(","):
            name = account.strip()
            if name and name not in primary and name not in extra_accounts:
                extra_accounts.append(name)
                extra_ids.extend(finding.evidence_ids)
    for account in extra_accounts:
        actions.append(
            Recommendation(
                title=f"Reset {account} and restrict where it can log on",
                detail=(
                    f"Set a new secret for {account} and limit the hosts allowed to use it. "
                    "The logs show the account authenticating from a workstation already on the suspicious path."
                ),
                evidence_ids=list(dict.fromkeys(extra_ids)),
            )
        )
    collection = [finding for finding in findings if finding.category == "collection"]
    if collection:
        actions.append(
            Recommendation(
                title="Review the sensitive share",
                detail="Check who can read the paths in the cited events and whether those reads were expected for that account.",
                evidence_ids=_ids(collection),
            )
        )
    transfers = [finding for finding in findings if finding.category == "exfiltration"]
    for finding in transfers:
        dest = finding.entities.get("dest_ip")
        actions.append(
            Recommendation(
                title=f"Review the transfer to {dest}",
                detail=(
                    f"Ask the network owners whether {dest} is an approved destination. "
                    "Block it if it is not, and keep the flow logs that correspond to the cited event."
                ),
                evidence_ids=list(finding.evidence_ids),
            )
        )
    actions.append(
        Recommendation(
            title="Attach the cited event ids to the ticket",
            detail="A later reader should be able to open every id in this report and land on the same log line.",
            evidence_ids=_ids(findings),
        )
    )
    return _dedupe(actions)


def _risk(findings: list[Finding]) -> tuple[str, str]:
    if not findings:
        return "low", "No detection rule fired, so the risk score from this rule set is low."
    highs = [finding.title for finding in findings if finding.severity == "high"]
    if highs:
        listed = "; ".join(highs)
        return "high", f"Risk is high because these findings are high severity: {listed}."
    titles = "; ".join(finding.title for finding in findings)
    return "medium", f"Risk is medium. The findings are {titles}."


def _root_cause(findings: list[Finding]) -> str:
    if not findings:
        return "No root cause is proposed, because no rule fired."
    access = next((finding for finding in findings if finding.category == "initial_access"), None)
    if access is None:
        return (
            "The findings share accounts and hosts inside the file, but no external authentication pattern was detected. "
            "Treat the cited events as the start of the timeline."
        )
    user = access.entities.get("user", "the account")
    src_ip = access.entities.get("src_ip", "the source address")
    workstation = access.entities.get("workstation") or access.entities.get("dest_host") or access.entities.get("host")
    return (
        f"The log-backed starting point is {user} authenticating from {src_ip}. "
        f"Later activity is included when it shares that account or originates at {workstation}. "
        "The logs do not show how the authentication secret was obtained."
    )


def _workstations(findings: list[Finding]) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    evidence: list[str] = []
    for finding in findings:
        candidates: list[str] = []
        if finding.category == "initial_access" and finding.entities.get("workstation"):
            candidates.append(finding.entities["workstation"])
        if finding.category in {"persistence", "exfiltration"} and finding.entities.get("host"):
            candidates.append(finding.entities["host"])
        if (
            finding.category == "privilege"
            and finding.entities.get("host")
            and not finding.entities["host"].upper().startswith("DC")
        ):
            candidates.append(finding.entities["host"])
        if finding.category == "lateral_movement" and finding.entities.get("src_host"):
            candidates.append(finding.entities["src_host"])
        if not any(host not in hosts for host in candidates):
            continue
        for host in candidates:
            if host not in hosts:
                hosts.append(host)
        evidence.extend(finding.evidence_ids)
    return hosts, list(dict.fromkeys(evidence))


def _ids(findings, categories: set[str] | None = None) -> list[str]:
    collected: list[str] = []
    for finding in findings:
        if categories is not None and finding.category not in categories:
            continue
        for event_id in finding.evidence_ids:
            if event_id not in collected:
                collected.append(event_id)
    return collected


def _dedupe(actions: list[Recommendation]) -> list[Recommendation]:
    seen: set[str] = set()
    unique: list[Recommendation] = []
    for action in actions:
        if action.title in seen:
            continue
        seen.add(action.title)
        unique.append(action)
    return unique

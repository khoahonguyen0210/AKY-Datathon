"""Build an attack-path graph whose edges cite parsed events."""

import re
from collections import defaultdict

from app.models import Event, Finding, Graph, GraphEdge, GraphNode

SHARE_RE = re.compile(r"\\\\[^\\]+\\([^\\]+)")
KIND_ORDER = {
    "external_ip": 0,
    "user": 1,
    "host": 2,
    "share": 3,
    "external_dest": 4,
}


def build_graph(events: list[Event], findings: list[Finding]) -> Graph:
    by_id = {event.id: event for event in events}
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str, bool], GraphEdge] = {}

    def ensure_node(node_id: str, label: str, kind: str, detail: str) -> GraphNode:
        existing = nodes.get(node_id)
        if existing is None:
            existing = GraphNode(id=node_id, label=label, kind=kind, detail=detail)  # type: ignore[arg-type]
            nodes[node_id] = existing
        return existing

    def ensure_edge(source: str, target: str, kind: str, label: str, evidence: list[str], denied: bool = False) -> None:
        if source == target:
            return
        key = (source, target, kind, denied)
        current = edges.get(key)
        if current is None:
            edge_id = f"{kind}:{source}->{target}" + (":denied" if denied else "")
            edges[key] = GraphEdge(
                id=edge_id,
                source=source,
                target=target,
                label=label,
                kind=kind,
                evidence_ids=list(dict.fromkeys(evidence)),
                denied=denied,
            )
            return
        for event_id in evidence:
            if event_id not in current.evidence_ids:
                current.evidence_ids.append(event_id)

    entry_users = {
        finding.entities.get("user")
        for finding in findings
        if finding.category == "initial_access" and finding.entities.get("user")
    }

    for finding in findings:
        related = [by_id[event_id] for event_id in finding.evidence_ids if event_id in by_id]
        if finding.category == "initial_access":
            _access_edges(finding, related, ensure_node, ensure_edge)
        elif finding.category == "privilege":
            _privilege_edges(finding, related, edges, ensure_node, ensure_edge)
        elif finding.category == "persistence":
            _flag_host(finding, ensure_node, "New service")
        elif finding.category == "lateral_movement":
            _lateral_edges(finding, related, entry_users, ensure_node, ensure_edge)
        elif finding.category == "collection":
            _collection_edges(related, ensure_node, ensure_edge)
        elif finding.category == "exfiltration":
            _transfer_edges(related, ensure_node, ensure_edge)

    _cover_missing(findings, by_id, nodes, edges, ensure_node, ensure_edge)
    _assign_positions(list(nodes.values()), list(edges.values()))
    ordered_nodes = sorted(nodes.values(), key=lambda node: (node.rank, node.lane, node.id))
    ordered_edges = sorted(edges.values(), key=lambda edge: edge.id)
    return Graph(nodes=ordered_nodes, edges=ordered_edges)


def _access_edges(finding: Finding, events: list[Event], ensure_node, ensure_edge) -> None:
    user = finding.entities.get("user")
    src_ip = finding.entities.get("src_ip")
    if not user:
        return
    user_id = f"user:{user}"
    ensure_node(user_id, user, "user", "Account named on the authentication events.")
    auth_events = [event for event in events if event.event_type.startswith("auth.logon")]
    failures = [event for event in auth_events if event.result == "failure"]
    if src_ip:
        ip_id = f"ip:{src_ip}"
        ensure_node(ip_id, src_ip, "external_ip", "Source address on the authentication events.")
        label = f"{len(failures)} failures, then success" if failures else "Successful authentication"
        ensure_edge(ip_id, user_id, "auth", label, [event.id for event in auth_events if event.event_type != "auth.logon.interactive"])
    for event in events:
        if event.event_type == "auth.logon.vpn" and event.result == "success":
            host_id = f"host:{event.host}"
            ensure_node(host_id, event.host, "host", "VPN gateway that accepted the session.")
            ensure_edge(user_id, host_id, "session", "VPN session", [event.id])
        if event.event_type == "auth.logon.interactive" and event.result == "success":
            host_id = f"host:{event.host}"
            ensure_node(host_id, event.host, "host", "Host where the interactive session started.")
            ensure_edge(user_id, host_id, "session", "Interactive session", [event.id])


def _privilege_edges(finding: Finding, events: list[Event], edges: dict, ensure_node, ensure_edge) -> None:
    host = finding.entities.get("host")
    actor = finding.entities.get("actor") or finding.entities.get("user")
    group = finding.entities.get("group")
    if not host or not actor:
        return
    host_id = f"host:{host}"
    actor_id = f"user:{actor}"
    flag = group or "Privileged change"
    ensure_node(actor_id, actor, "user", "Account that performed the group change.")
    node = ensure_node(host_id, host, "host", "Host where a privileged group changed.")
    if flag not in node.flags:
        node.flags.append(flag)
    source = actor_id
    src_host = finding.entities.get("src_host")
    evidence = [event.id for event in events]
    if src_host and src_host != host and actor and actor not in {finding.entities.get("subject")}:
        # Keep the account downstream of the workstation it was used from.
        src_id = f"host:{src_host}"
        ensure_node(src_id, src_host, "host", "Workstation already on the path.")
        ensure_edge(src_id, actor_id, "account", f"Used {actor}", evidence)
    label = f"Added to {group}" if group else "Privilege change"
    # A second arrow onto a host that already has a session edge only piles labels.
    if not _attach(edges, source, host_id, evidence):
        ensure_edge(source, host_id, "privilege", label, evidence)


def _attach(edges: dict, source: str, target: str, evidence: list[str]) -> bool:
    for edge in edges.values():
        if edge.source == source and edge.target == target and not edge.denied:
            for event_id in evidence:
                if event_id not in edge.evidence_ids:
                    edge.evidence_ids.append(event_id)
            return True
    return False


def _lateral_edges(finding: Finding, events: list[Event], entry_users: set[str | None], ensure_node, ensure_edge) -> None:
    source = finding.entities.get("src_host")
    dest = finding.entities.get("dest_host")
    if not source or not dest:
        return
    source_id = f"host:{source}"
    dest_id = f"host:{dest}"
    ensure_node(source_id, source, "host", "Host that initiated the network logon.")
    ensure_node(dest_id, dest, "host", "Host that received the network logon.")
    denied = [event for event in events if event.result == "failure"]
    allowed = [event for event in events if event.result != "failure"]
    if denied:
        who = ", ".join(_names(denied)) or "account"
        ensure_edge(source_id, dest_id, "lateral", f"{who} denied", [event.id for event in denied], denied=True)
    if allowed:
        who = ", ".join(_names(allowed)) or "account"
        ensure_edge(source_id, dest_id, "lateral", f"{who} logon", [event.id for event in allowed])
        for event in allowed:
            if event.user and event.user not in entry_users:
                user_id = f"user:{event.user}"
                ensure_node(user_id, event.user, "user", "Second account used from a host already on the path.")
                ensure_edge(source_id, user_id, "account", f"Authenticated as {event.user}", [event.id])


def _collection_edges(events: list[Event], ensure_node, ensure_edge) -> None:
    for event in events:
        share = _share_name(event.detail)
        host = event.dest_host or event.host
        host_id = f"host:{host}"
        ensure_node(host_id, host, "host", "Host that stored the cited files.")
        if not share:
            continue
        share_id = f"share:{host}/{share}"
        ensure_node(share_id, share, "share", "Share named in the file-access events.")
        ensure_edge(host_id, share_id, "access", "Sensitive read", [event.id])


def _transfer_edges(events: list[Event], ensure_node, ensure_edge) -> None:
    for event in events:
        if not event.dest_ip:
            continue
        host_id = f"host:{event.host}"
        dest_id = f"ip:{event.dest_ip}"
        ensure_node(host_id, event.host, "host", "Host that sent the transfer.")
        ensure_node(dest_id, event.dest_ip, "external_dest", "Destination recorded on the transfer event.")
        ensure_edge(host_id, dest_id, "transfer", "Outbound transfer", [event.id])


def _flag_host(finding: Finding, ensure_node, flag: str) -> None:
    host = finding.entities.get("host")
    if not host:
        return
    node = ensure_node(f"host:{host}", host, "host", "Host named by a service-install event.")
    if flag not in node.flags:
        node.flags.append(flag)


def _cover_missing(findings, by_id, nodes, edges, ensure_node, ensure_edge) -> None:
    covered = {event_id for edge in edges.values() for event_id in edge.evidence_ids}
    for finding in findings:
        for event_id in finding.evidence_ids:
            if event_id in covered or event_id not in by_id:
                continue
            event = by_id[event_id]
            host_id = f"host:{event.host}"
            host_edges = [
                edge for edge in edges.values() if edge.source == host_id or edge.target == host_id
            ]
            if host_edges:
                host_edges[0].evidence_ids.append(event_id)
                covered.add(event_id)
                continue
            user = event.user or "account"
            user_id = f"user:{user}"
            ensure_node(user_id, user, "user", "Account cited by an event that needed a graph edge.")
            ensure_node(host_id, event.host, "host", "Host cited by an event that needed a graph edge.")
            ensure_edge(user_id, host_id, "related", "Cited event", [event_id])
            covered.add(event_id)


def _assign_positions(nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
    if not nodes:
        return
    preds: dict[str, set[str]] = {node.id: set() for node in nodes}
    succs: dict[str, set[str]] = {node.id: set() for node in nodes}
    known = set(preds)
    for edge in edges:
        if edge.source in known and edge.target in known and edge.source != edge.target:
            preds[edge.target].add(edge.source)
            succs[edge.source].add(edge.target)

    indegree = {node_id: len(preds[node_id]) for node_id in known}
    queue = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
    topo: list[str] = []
    while queue:
        node_id = queue.pop(0)
        topo.append(node_id)
        for successor in sorted(succs[node_id]):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                queue.append(successor)
                queue.sort()
    if len(topo) != len(nodes):
        for node in nodes:
            node.rank = KIND_ORDER[node.kind]
        _lanes(nodes)
        return

    rank = {node_id: 0 for node_id in known}
    for node_id in topo:
        if preds[node_id]:
            rank[node_id] = 1 + max(rank[parent] for parent in preds[node_id])
    host_ranks = [rank[node.id] for node in nodes if node.kind == "host"]
    if host_ranks:
        floor = max(host_ranks) + 1
        for node in nodes:
            if node.kind == "external_dest":
                rank[node.id] = max(rank[node.id], floor)
    for node in nodes:
        node.rank = rank[node.id]
    _lanes(nodes)


def _lanes(nodes: list[GraphNode]) -> None:
    grouped: dict[int, list[GraphNode]] = defaultdict(list)
    for node in nodes:
        grouped[node.rank].append(node)
    for group in grouped.values():
        group.sort(key=lambda node: (KIND_ORDER[node.kind], node.label, node.id))
        for lane, node in enumerate(group):
            node.lane = lane


def _share_name(detail: str) -> str | None:
    match = SHARE_RE.search(detail)
    if not match:
        return None
    return match.group(1)


def _names(events: list[Event]) -> list[str]:
    names: list[str] = []
    for event in events:
        if event.user and event.user not in names:
            names.append(event.user)
    return names

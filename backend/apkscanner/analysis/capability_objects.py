"""Extract first-class capability objects from chain analysis results.

Replaces raw regex markers for PendingIntent, URI Grant, and other
Android IPC capabilities with structured entities that track creator
identity, escape path, mutability, and use sites.
"""

from __future__ import annotations

from typing import Any

_CAPABILITY_CHAIN_KINDS = frozenset(
    {
        "pending_intent_delegation",
        "uri_permission_redelegation",
        "nested_intent_redirection",
        "activity_result_content_proxy",
    }
)

_CREATOR_MARKERS = frozenset(
    {
        "pending_intent_create",
        "uri_grant",
        "uri_grant_persisted",
        "nested_intent_input",
        "activity_result_input",
    }
)

_MUTABLE_MARKERS = frozenset(
    {
        "pending_intent_mutable",
        "pending_allow_unsafe_implicit",
        "pending_base_implicit",
    }
)

_GUARD_MARKERS = frozenset(
    {
        "pending_intent_immutable",
        "pending_intent_one_shot",
        "pending_base_explicit",
        "explicit_intent_target",
        "content_authority_guard",
    }
)


def extract_capability_objects(
    chain_candidates: list[dict[str, Any]],
    nodes: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract capability objects from chain analysis results.

    Each capability object captures the lifecycle of a cross-process
    capability: who created it, where it escapes, whether it is mutable,
    and where it is ultimately used.

    Args:
        chain_candidates: Chain analysis results from
            ``AndroidAttackChainAnalyzer.analyze()``.
        nodes: CodeNode dict from ``AndroidAttackChainAnalyzer._index_nodes()``.

    Returns:
        A list of capability-object dicts suitable for serialisation.
    """
    capabilities: list[dict[str, Any]] = []

    for chain in chain_candidates:
        if chain.get("chain_kind") not in _CAPABILITY_CHAIN_KINDS:
            continue

        kind = chain["chain_kind"]
        cap_type = _capability_type_for_chain(kind)
        if cap_type is None:
            continue

        classes = _class_names(chain)
        source_markers = set(chain.get("sources", []) or chain.get("source_markers", []))
        sink_markers = set(chain.get("sinks", []) or chain.get("sink_markers", []))
        risk_markers = set(chain.get("risks", []) or chain.get("risk_markers", []))
        guard_markers = set(chain.get("guards", []) or chain.get("guard_markers", []))

        all_markers = source_markers | sink_markers | risk_markers | guard_markers
        creator_class = _find_creator_class(classes, nodes, all_markers & _CREATOR_MARKERS)
        holder_class = classes[-1] if len(classes) > 1 else None

        target = _infer_target(chain, nodes, classes)

        mutable = bool(risk_markers & _MUTABLE_MARKERS)
        guarded = bool(guard_markers & _GUARD_MARKERS)

        escape_path = list(classes)
        use_sites = _collect_use_sites(chain, nodes, classes)

        locations = _collect_locations(chain, nodes, classes)

        capabilities.append(
            {
                "capability_type": cap_type,
                "creator_class": creator_class or (classes[0] if classes else "unknown"),
                "creator_method": _creator_method(chain, nodes, creator_class, all_markers),
                "holder_class": holder_class,
                "target": target,
                "mutable": mutable and not guarded,
                "escape_path": escape_path,
                "use_sites": use_sites,
                "chain_kind": kind,
                "risk_markers": sorted(risk_markers),
                "guard_markers": sorted(guard_markers),
                "locations": locations,
            }
        )

    return capabilities


def _class_names(chain: dict[str, Any]) -> list[str]:
    """Extract class names from chain candidate path entries."""
    path_entries = chain.get("path") or []
    return [entry["class_name"] for entry in path_entries if isinstance(entry, dict) and entry.get("class_name")]


def _capability_type_for_chain(chain_kind: str) -> str | None:
    if chain_kind == "pending_intent_delegation":
        return "pending_intent"
    if chain_kind in {"uri_permission_redelegation", "activity_result_content_proxy"}:
        return "content_uri_grant"
    if chain_kind == "nested_intent_redirection":
        return "pending_intent"
    return None


def _find_creator_class(
    classes: list[str],
    nodes: dict[str, Any],
    creator_markers: set[str],
) -> str | None:
    for cls in classes:
        node = nodes.get(cls)
        if node is None:
            continue
        if set(getattr(node, "markers", {})) & creator_markers:
            return cls
    return None


def _infer_target(
    chain: dict[str, Any],
    nodes: dict[str, Any],
    classes: list[str],
) -> str | None:
    """Infer the capability target from risk markers and chain classes."""
    risk_markers = set(chain.get("risks", []) or chain.get("risk_markers", []))
    if "pending_base_implicit" in risk_markers:
        return "implicit_intent"
    if "uri_grant" in risk_markers or "uri_grant_persisted" in risk_markers:
        for cls in classes:
            node = nodes.get(cls)
            if node is None:
                continue
            for evidence_list in getattr(node, "markers", {}).values():
                for evidence in evidence_list:
                    if isinstance(evidence, dict) and evidence.get("detail"):
                        detail = str(evidence["detail"])
                        if "content://" in detail or "file://" in detail:
                            return detail
    return None


def _creator_method(
    chain: dict[str, Any],
    nodes: dict[str, Any],
    creator_class: str | None,
    markers: set[str],
) -> str | None:
    if creator_class is None:
        return None
    node = nodes.get(creator_class)
    if node is None:
        return None
    for marker in markers & _CREATOR_MARKERS:
        for evidence in getattr(node, "markers", {}).get(marker, []):
            if isinstance(evidence, dict) and evidence.get("method"):
                return str(evidence["method"])
    return None


def _collect_use_sites(
    chain: dict[str, Any],
    nodes: dict[str, Any],
    classes: list[str],
) -> list[str]:
    use_sites: list[str] = []
    sink_markers = set(chain.get("sinks", []) or chain.get("sink_markers", []))
    for cls in classes:
        node = nodes.get(cls)
        if node is None:
            continue
        node_markers = set(getattr(node, "markers", {}))
        if node_markers & sink_markers:
            use_sites.append(cls)
    return use_sites


def _collect_locations(
    chain: dict[str, Any],
    nodes: dict[str, Any],
    classes: list[str],
) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for cls in classes:
        node = nodes.get(cls)
        if node is None:
            continue
        for evidence_list in getattr(node, "markers", {}).values():
            for evidence in evidence_list:
                if not isinstance(evidence, dict):
                    continue
                key = (str(evidence.get("path", "")), int(evidence.get("line", 0)))
                if key in seen or key[1] == 0:
                    continue
                seen.add(key)
                locations.append(
                    {
                        "class_name": cls,
                        "path": evidence.get("path", ""),
                        "line": evidence.get("line", 0),
                        "marker": evidence.get("marker", ""),
                    }
                )
    return locations[:32]
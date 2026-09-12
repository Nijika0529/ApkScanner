from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..core.enums import EntryPointKind, TaskStatus, TaskType
from ..core.models import EntryPoint, InvestigationTask

# Standalone chain sites (those whose handler has no component task) are admitted
# in priority order; the rest stay as inventory surfaces instead of consuming
# devices and Agent turns.
DEFAULT_MAX_STANDALONE_CHAIN_SITES = 12

# Curated from the Android Manifest.permission API reference. Keep unknown
# framework/OEM permissions unresolved so they continue to Agent review.
# https://developer.android.com/reference/android/Manifest.permission
FRAMEWORK_STRONG_COMPONENT_PERMISSIONS: dict[str, str] = {
    "android.permission.BIND_AUTOFILL_SERVICE": "signature",
    "android.permission.BIND_CALL_REDIRECTION_SERVICE": "signature|privileged",
    "android.permission.BIND_CARRIER_MESSAGING_CLIENT_SERVICE": "signature",
    "android.permission.BIND_CARRIER_SERVICES": "signature|privileged",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE": "signature",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE": "signature",
    "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE": "signature",
    "android.permission.BIND_DEVICE_ADMIN": "signature",
    "android.permission.BIND_DREAM_SERVICE": "signature",
    "android.permission.BIND_INCALL_SERVICE": "signature|privileged",
    "android.permission.BIND_INPUT_METHOD": "signature",
    "android.permission.BIND_MIDI_DEVICE_SERVICE": "signature",
    "android.permission.BIND_NFC_SERVICE": "signature",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "signature",
    "android.permission.BIND_PRINT_SERVICE": "signature",
    "android.permission.BIND_QUICK_ACCESS_WALLET_SERVICE": "signature",
    "android.permission.BIND_REMOTEVIEWS": "signature|privileged",
    "android.permission.BIND_SCREENING_SERVICE": "signature|privileged",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE": "signature|privileged",
    "android.permission.BIND_TEXT_SERVICE": "signature",
    "android.permission.BIND_TV_AD_SERVICE": "signature|privileged",
    "android.permission.BIND_TV_INPUT": "signature|privileged",
    "android.permission.BIND_TV_INTERACTIVE_APP": "signature|privileged",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE": "signature|privileged",
    "android.permission.BIND_VOICE_INTERACTION": "signature",
    "android.permission.BIND_VPN_SERVICE": "signature",
    "android.permission.BIND_VR_LISTENER_SERVICE": "signature",
    "android.permission.BIND_WALLPAPER": "signature|privileged",
}


@dataclass(frozen=True, slots=True)
class StaticEntryClosure:
    entry_point_id: str
    kind: str
    name: str
    reason_code: str
    reason: str
    permission: str | None = None
    permission_protection: str | None = None
    resolution_source: str = "manifest"

    def as_dict(self) -> dict[str, str | None]:
        return {
            "entry_point_id": self.entry_point_id,
            "kind": self.kind,
            "name": self.name,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "permission": self.permission,
            "permission_protection": self.permission_protection,
            "resolution_source": self.resolution_source,
        }


@dataclass(slots=True)
class InvestigationPlan:
    tasks: list[InvestigationTask] = field(default_factory=list)
    static_closures: list[StaticEntryClosure] = field(default_factory=list)
    coalescing_decisions: list[dict[str, object]] = field(default_factory=list)
    chain_site_total: int = 0
    chain_site_dispatched: int = 0
    chain_site_merged_into_component: int = 0
    chain_site_deferred: int = 0


class InvestigationPlanner:
    def __init__(
        self,
        *,
        android_version: str,
        adb_configured: bool,
        android_api: int = 36,
        device_reset_policy: str = "never",
        max_standalone_chain_sites: int = DEFAULT_MAX_STANDALONE_CHAIN_SITES,
    ):
        self.android_version = android_version
        self.android_api = android_api
        self.adb_configured = adb_configured
        self.device_reset_policy = device_reset_policy
        self.max_standalone_chain_sites = max(0, int(max_standalone_chain_sites))

    def plan(self, scan_id: str, entries: list[EntryPoint]) -> list[InvestigationTask]:
        return self.plan_with_decisions(scan_id, entries).tasks

    def plan_with_decisions(
        self,
        scan_id: str,
        entries: list[EntryPoint],
    ) -> InvestigationPlan:
        plan = InvestigationPlan()
        deep_links_by_owner: dict[str, list[EntryPoint]] = defaultdict(list)
        component_tasks_by_name: dict[str, InvestigationTask] = {}
        for entry in entries:
            if entry.kind == EntryPointKind.STATIC_SURFACE.value:
                if (entry.metadata_json or {}).get("static_review_rollup") is True:
                    # Roll-up surfaces keep family coverage and version diffing
                    # but are not dispatched; per-site surfaces carry dispatch.
                    continue
                plan.tasks.append(self._static_review_task(scan_id, entry))
                continue
            closure = self._static_closure(entry)
            if closure is not None:
                plan.static_closures.append(closure)
                continue
            if entry.kind == EntryPointKind.DEEP_LINK.value:
                deep_links_by_owner[entry.owner_component or entry.name].append(entry)
                continue
            task = self._component_task(scan_id, entry)
            plan.tasks.append(task)
            component_tasks_by_name[entry.name] = task
        for owner, deep_links in deep_links_by_owner.items():
            owner_task = component_tasks_by_name.get(owner)
            if owner_task is None:
                plan.tasks.append(self._deep_link_task(scan_id, owner, deep_links))
                continue
            owner_task.target_entry_ids = [
                *owner_task.target_entry_ids,
                *(entry.id for entry in deep_links),
            ]
            owner_task.hypotheses = [
                *owner_task.hypotheses,
                *self._deep_link_hypotheses(owner)[1:],
            ]
            owner_task.priority = max(owner_task.priority, 98)
        # Chain sites fold into the component task that owns their handler; only
        # sites without a component task become standalone, and those are admitted
        # by priority so granularity does not explode the task count.
        plan.tasks, attachment_decisions = self._attach_chain_sites(plan.tasks, entries)
        plan.tasks, group_decisions = self._coalesce_explicit_groups(plan.tasks, entries)
        plan.tasks, deferred_chain_entries = self._admit_standalone_chain_sites(
            plan.tasks,
            entries,
        )
        plan.coalescing_decisions = [*attachment_decisions, *group_decisions]
        plan.chain_site_total = sum(
            1
            for entry in entries
            if isinstance((entry.metadata_json or {}).get("static_review_site"), dict)
        )
        plan.chain_site_merged_into_component = sum(
            int(item.get("merged_entry_count") or 0)
            for item in attachment_decisions
            if item.get("strategy") == "component_handler_site"
        )
        plan.chain_site_deferred = deferred_chain_entries
        plan.chain_site_dispatched = max(
            0,
            plan.chain_site_total - plan.chain_site_deferred,
        )
        return plan

    @staticmethod
    def _chain_site_of(entry: EntryPoint) -> dict[str, Any] | None:
        site = (entry.metadata_json or {}).get("static_review_site")
        return site if isinstance(site, dict) else None

    @classmethod
    def _task_chain_site(
        cls,
        task: InvestigationTask,
        entries_by_id: dict[str, EntryPoint],
    ) -> dict[str, Any] | None:
        if task.task_type != TaskType.STATIC_REVIEW.value:
            return None
        for entry_id in task.target_entry_ids:
            entry = entries_by_id.get(entry_id)
            if entry is None:
                continue
            site = cls._chain_site_of(entry)
            if site is not None:
                return site
        return None

    @classmethod
    def _attach_chain_sites(
        cls,
        tasks: list[InvestigationTask],
        entries: list[EntryPoint],
    ) -> tuple[list[InvestigationTask], list[dict[str, object]]]:
        entries_by_id = {entry.id: entry for entry in entries}
        component_by_handler: dict[str, InvestigationTask] = {}
        for task in tasks:
            if task.task_type != TaskType.COMPONENT.value:
                continue
            for entry_id in task.target_entry_ids:
                entry = entries_by_id.get(entry_id)
                if entry is None:
                    continue
                component_by_handler.setdefault(entry.name, task)
                if entry.owner_component:
                    component_by_handler.setdefault(entry.owner_component, task)

        attached: set[int] = set()
        handler_tasks: dict[str, InvestigationTask] = {}
        decisions: list[dict[str, object]] = []
        for task in tasks:
            site = cls._task_chain_site(task, entries_by_id)
            if site is None:
                continue
            handler = str(site.get("handler_class") or site.get("handler") or "")
            owner = component_by_handler.get(handler)
            if owner is None:
                existing = handler_tasks.get(handler)
                if existing is None:
                    handler_tasks[handler] = task
                    continue
                strategy = "same_handler_site"
                reason = (
                    f"chain site {site.get('site_key')} shares handler {handler} "
                    "with another chain site in this scan"
                )
                base = existing
            else:
                strategy = "component_handler_site"
                reason = (
                    f"chain site {site.get('site_key')} belongs to the component task "
                    f"that already investigates handler {handler}"
                )
                base = owner
            merged = cls._merge_tasks(base, task, reason=reason, strategy=strategy)
            attached.add(id(task))
            decisions.append(merged)

        remaining = [task for task in tasks if id(task) not in attached]
        return remaining, decisions

    @staticmethod
    def _merge_tasks(
        base: InvestigationTask,
        extra: InvestigationTask,
        *,
        strategy: str,
        reason: str,
    ) -> dict[str, object]:
        base.target_entry_ids = list(
            dict.fromkeys([*base.target_entry_ids, *extra.target_entry_ids])
        )
        base.hypotheses = list(dict.fromkeys([*base.hypotheses, *extra.hypotheses]))
        base.allowed_side_effects = list(
            dict.fromkeys([*base.allowed_side_effects, *extra.allowed_side_effects])
        )
        base.priority = max(int(base.priority or 0), int(extra.priority or 0))
        preconditions = dict(base.preconditions or {})
        attachments = list(preconditions.get("chain_site_attachments") or [])
        attachments.append(
            {
                "strategy": strategy,
                "reason": reason,
                "merged_task_id": extra.id,
                "merged_entry_ids": list(extra.target_entry_ids),
            }
        )
        base.preconditions = {**preconditions, "chain_site_attachments": attachments}
        return {
            "group_key": f"chain-site:{extra.id}",
            "strategy": strategy,
            "reason": reason,
            "source_task_count": 2,
            "result_task_count": 1,
            "avoided_task_count": 1,
            "merged_entry_count": len(extra.target_entry_ids),
            "entry_point_ids": list(extra.target_entry_ids),
        }

    def _admit_standalone_chain_sites(
        self,
        tasks: list[InvestigationTask],
        entries: list[EntryPoint],
    ) -> tuple[list[InvestigationTask], int]:
        entries_by_id = {entry.id: entry for entry in entries}
        standalone = [
            task
            for task in tasks
            if self._task_chain_site(task, entries_by_id) is not None
        ]
        if len(standalone) <= self.max_standalone_chain_sites:
            return tasks, 0
        standalone.sort(key=lambda task: (-int(task.priority or 0), str(task.id)))
        kept = {id(task) for task in standalone[: self.max_standalone_chain_sites]}
        deferred = [task for task in standalone if id(task) not in kept]
        deferred_ids = {id(task) for task in deferred}
        deferred_entry_count = sum(len(task.target_entry_ids) for task in deferred)
        remaining = [task for task in tasks if id(task) not in deferred_ids]
        return remaining, deferred_entry_count

    @staticmethod
    def _coalesce_explicit_groups(
        tasks: list[InvestigationTask],
        entries: list[EntryPoint],
    ) -> tuple[list[InvestigationTask], list[dict[str, object]]]:
        """Merge only profile-declared equivalent attack-chain variants.

        Every merged entry remains assigned to the resulting task, and the reason is
        persisted in task preconditions so cost reduction never becomes silent coverage loss.
        """

        entries_by_id = {entry.id: entry for entry in entries}
        task_groups: dict[int, str] = {}
        group_metadata: dict[str, dict[str, object]] = {}
        grouped_tasks: dict[str, list[InvestigationTask]] = defaultdict(list)
        for task in tasks:
            declarations = [
                (entries_by_id[entry_id].metadata_json or {}).get(
                    "investigation_group"
                )
                for entry_id in task.target_entry_ids
                if entry_id in entries_by_id
            ]
            declarations = [item for item in declarations if isinstance(item, dict)]
            keys = {
                str(item.get("key"))
                for item in declarations
                if item.get("key")
            }
            if len(keys) != 1:
                continue
            key = next(iter(keys))
            task_groups[id(task)] = key
            grouped_tasks[key].append(task)
            group_metadata.setdefault(key, dict(declarations[0]))

        decisions: list[dict[str, object]] = []
        replacements: dict[str, InvestigationTask] = {}
        for key, candidates in grouped_tasks.items():
            if len(candidates) < 2:
                continue
            base = max(
                candidates,
                key=lambda task: (
                    task.task_type != TaskType.STATIC_REVIEW.value,
                    task.task_type == TaskType.COMPONENT.value,
                    task.priority,
                ),
            )
            target_entry_ids = list(
                dict.fromkeys(
                    entry_id
                    for task in candidates
                    for entry_id in task.target_entry_ids
                )
            )
            hypotheses = list(
                dict.fromkeys(
                    hypothesis
                    for task in candidates
                    for hypothesis in task.hypotheses
                )
            )
            allowed_side_effects = list(
                dict.fromkeys(
                    side_effect
                    for task in candidates
                    for side_effect in task.allowed_side_effects
                )
            )
            variants = [
                {
                    "entry_point_id": entry_id,
                    "kind": entries_by_id[entry_id].kind,
                    "name": entries_by_id[entry_id].name,
                    "owner_component": entries_by_id[entry_id].owner_component,
                }
                for entry_id in target_entry_ids
                if entry_id in entries_by_id
            ]
            static_families = list(
                dict.fromkeys(
                    str((entries_by_id[entry_id].metadata_json or {}).get("static_review_family"))
                    for entry_id in target_entry_ids
                    if entry_id in entries_by_id
                    and (entries_by_id[entry_id].metadata_json or {}).get(
                        "static_review_family"
                    )
                )
            )
            metadata = group_metadata[key]
            base.target_entry_ids = target_entry_ids
            base.hypotheses = hypotheses
            base.priority = max(task.priority for task in candidates)
            base.allowed_side_effects = allowed_side_effects
            base.preconditions = {
                **dict(base.preconditions or {}),
                "coalescing": {
                    "group_key": key,
                    "strategy": metadata.get("strategy"),
                    "reason": metadata.get("reason"),
                    "source_task_count": len(candidates),
                    "merged_entry_count": len(target_entry_ids),
                    "variants": variants,
                    "static_families": static_families,
                },
            }
            replacements[key] = base
            decisions.append(
                {
                    "group_key": key,
                    "strategy": metadata.get("strategy"),
                    "reason": metadata.get("reason"),
                    "source_task_count": len(candidates),
                    "result_task_count": 1,
                    "avoided_task_count": len(candidates) - 1,
                    "entry_point_ids": target_entry_ids,
                    "entry_names": [item["name"] for item in variants],
                }
            )

        emitted_groups: set[str] = set()
        coalesced: list[InvestigationTask] = []
        for task in tasks:
            key = task_groups.get(id(task))
            replacement = replacements.get(key or "")
            if replacement is None:
                coalesced.append(task)
                continue
            if key in emitted_groups:
                continue
            emitted_groups.add(str(key))
            coalesced.append(replacement)
        return coalesced, decisions

    @classmethod
    def _static_closure(cls, entry: EntryPoint) -> StaticEntryClosure | None:
        if entry.kind == EntryPointKind.STATIC_SURFACE.value:
            return None
        if (entry.metadata_json or {}).get("effective_enabled") is False:
            return StaticEntryClosure(
                entry_point_id=entry.id,
                kind=entry.kind,
                name=entry.name,
                reason_code="component_disabled",
                reason="组件或应用已禁用，普通第三方应用无法到达该入口。",
            )
        if not entry.exported:
            return StaticEntryClosure(
                entry_point_id=entry.id,
                kind=entry.kind,
                name=entry.name,
                reason_code="not_exported",
                reason="组件未导出，普通第三方应用无法直接调用该入口。",
            )
        if entry.kind == EntryPointKind.PROVIDER.value:
            if cls._provider_can_grant_uri(entry):
                return None
            resolved = cls._resolved_provider_protection(entry)
        else:
            resolved = cls._resolved_protection(entry)
        if resolved is None:
            return None
        protection, source = resolved
        if not cls._is_strong_protection(protection):
            return None
        return StaticEntryClosure(
            entry_point_id=entry.id,
            kind=entry.kind,
            name=entry.name,
            reason_code="strong_permission_guard",
            reason=(
                f"入口受 {entry.permission}（{protection}）保护；在 ordinary_app_uid "
                "威胁模型下，普通第三方应用无法直接调用。"
            ),
            permission=entry.permission,
            permission_protection=protection,
            resolution_source=source,
        )

    @staticmethod
    def _resolved_protection(entry: EntryPoint) -> tuple[str, str] | None:
        return InvestigationPlanner._resolved_named_protection(
            entry.permission,
            entry.permission_protection,
        )

    @staticmethod
    def _resolved_named_protection(
        permission: str | None,
        declared_protection: str | None,
    ) -> tuple[str, str] | None:
        if declared_protection:
            return declared_protection, "manifest_declaration"
        if permission in FRAMEWORK_STRONG_COMPONENT_PERMISSIONS:
            return (
                FRAMEWORK_STRONG_COMPONENT_PERMISSIONS[permission],
                "android_framework_catalog",
            )
        return None

    @classmethod
    def _resolved_provider_protection(
        cls,
        entry: EntryPoint,
    ) -> tuple[str, str] | None:
        metadata = entry.metadata_json or {}
        boundaries: list[tuple[str | None, str | None]] = [
            (
                metadata.get("effective_read_permission"),
                metadata.get("effective_read_permission_protection"),
            ),
            (
                metadata.get("effective_write_permission"),
                metadata.get("effective_write_permission_protection"),
            ),
        ]
        for path in metadata.get("path_permissions") or []:
            if not isinstance(path, dict):
                return None
            boundaries.extend(
                [
                    (
                        path.get("effective_read_permission"),
                        path.get("effective_read_permission_protection"),
                    ),
                    (
                        path.get("effective_write_permission"),
                        path.get("effective_write_permission_protection"),
                    ),
                ]
            )
        if not any(permission is not None for permission, _protection in boundaries):
            return cls._resolved_protection(entry)

        resolved: list[tuple[str, str]] = []
        for permission, protection in boundaries:
            item = cls._resolved_named_protection(permission, protection)
            if item is None or not cls._is_strong_protection(item[0]):
                return None
            resolved.append(item)
        protections = sorted({item[0] for item in resolved})
        sources = sorted({item[1] for item in resolved})
        return "|".join(protections), "+".join(sources)

    @staticmethod
    def _is_strong_protection(value: str) -> bool:
        normalized = (
            value.strip()
            .lower()
            .replace("_", "")
            .replace("-", "")
            .replace(" ", "")
        )
        base = normalized.split("|", 1)[0]
        return base in {"signature", "signatureorsystem", "knownsigner", "internal"}

    @staticmethod
    def _provider_can_grant_uri(entry: EntryPoint) -> bool:
        metadata = entry.metadata_json or {}
        grant_all = str(metadata.get("grant_uri_permissions") or "").strip().lower()
        return grant_all == "true" or bool(metadata.get("grant_uri_permission_paths"))

    def _base(self) -> dict:
        allowed_side_effects = [
            "install_target_apk",
            "build_platform_proof_harness",
            "install_platform_proof_harness",
            "uninstall_platform_proof_harness",
            "build_agent_poc_apk",
            "install_agent_poc_apk",
            "uninstall_agent_poc_apk",
            "test_backend_mutations_with_cleanup",
            "adb_exploration",
        ]
        if self.device_reset_policy != "never":
            allowed_side_effects.append("clear_application_data")
        return {
            "status": TaskStatus.QUEUED.value,
            "preconditions": {"ordinary_app_caller": True},
            "allowed_side_effects": allowed_side_effects,
            "device_profile": {
                "android_version": self.android_version,
                "api_level": self.android_api,
                "minimum_validation_api": 36,
                "root_capable": True,
                "reset_capability": (
                    "disabled_preserve_target_state"
                    if self.device_reset_policy == "never"
                    else "pm_clear_only"
                ),
                "configured": self.adb_configured,
            },
        }

    def _component_task(self, scan_id: str, entry: EntryPoint) -> InvestigationTask:
        hypotheses = [
            *{
            EntryPointKind.ACTIVITY.value: [
                "A third-party application can launch the activity.",
                (
                    "External extras, URI data, or callback results can bypass authentication, "
                    "caller binding, transaction state, or reach a sensitive screen."
                ),
                (
                    "Nested intents, URI grants, internal component redirects, or WebView "
                    "navigation can cross a trust boundary and reach a sensitive sink."
                ),
            ],
            EntryPointKind.ACTIVITY_ALIAS.value: [
                "The alias exposes its target activity under weaker authorization controls.",
                "Intent data or extras reach sensitive target behavior.",
            ],
            EntryPointKind.SERVICE.value: [
                "A third-party application can start or bind to the service.",
                "The service performs or returns sensitive behavior without caller authorization.",
                (
                    "Every Binder transaction binds the real calling UID to an authorized package "
                    "and does not trust caller-supplied identity fields."
                ),
            ],
            EntryPointKind.RECEIVER.value: [
                "An untrusted application can deliver a broadcast to the receiver.",
                "Attacker-controlled extras trigger a sensitive or persistent side effect.",
                (
                    "Payload authentication cannot be forged with APK-embedded material and "
                    "freshness or version checks prevent replay and update lockout."
                ),
            ],
            EntryPointKind.PROVIDER.value: [
                "An untrusted application can query or open provider data.",
                "Provider paths, selections, or URI grants expose data or permit injection.",
            ],
            }[entry.kind],
            (
                "Attacker-controlled data from this assigned entry can traverse helper classes, "
                "non-exported components, WebView or Binder boundaries, files, databases, or "
                "other application code and reach a concrete sensitive sink."
            ),
        ]
        priority = {
            EntryPointKind.PROVIDER.value: 95,
            EntryPointKind.SERVICE.value: 90,
            EntryPointKind.ACTIVITY.value: 80,
            EntryPointKind.ACTIVITY_ALIAS.value: 80,
            EntryPointKind.RECEIVER.value: 75,
        }[entry.kind]
        return InvestigationTask(
            scan_id=scan_id,
            task_type=TaskType.COMPONENT.value,
            priority=priority,
            target_entry_ids=[entry.id],
            hypotheses=hypotheses,
            **self._base(),
        )

    def _static_review_task(
        self,
        scan_id: str,
        entry: EntryPoint,
    ) -> InvestigationTask:
        metadata = entry.metadata_json or {}
        hypotheses = [
            str(value)
            for value in metadata.get("static_review_hypotheses", [])
            if isinstance(value, str)
        ]
        site = metadata.get("static_review_site")
        if isinstance(site, dict):
            hypotheses = list(
                dict.fromkeys(
                    [
                        (
                            f"处理程序 {site.get('handler')} 到 sink {site.get('sink')} "
                            "的攻击链是否可被普通第三方应用到达，并产生具体未授权影响。"
                        ),
                        *hypotheses,
                    ]
                )
            )
        if not hypotheses:
            hypotheses = [
                "The assigned static code signal participates in a reachable security boundary.",
                "The signal has concrete unauthorized confidentiality, integrity, or privilege impact.",
            ]
        return InvestigationTask(
            scan_id=scan_id,
            task_type=TaskType.STATIC_REVIEW.value,
            priority=int(metadata.get("static_review_priority") or 85),
            target_entry_ids=[entry.id],
            hypotheses=hypotheses,
            preconditions={
                "ordinary_app_caller": True,
                "static_semantic_seed": True,
                "family": metadata.get("static_review_family"),
                "rule_ids": list(metadata.get("static_review_rule_ids") or []),
                **(
                    {
                        "chain_site": site,
                        "parent_surface": metadata.get("static_review_parent_surface"),
                    }
                    if isinstance(site, dict)
                    else {}
                ),
            },
            allowed_side_effects=[],
            device_profile={
                "android_version": self.android_version,
                "api_level": self.android_api,
                "minimum_validation_api": 36,
                "root_capable": False,
                "reset_capability": "not_applicable",
                "configured": self.adb_configured,
                "static_review": True,
            },
        )

    def _deep_link_task(
        self, scan_id: str, owner: str, deep_links: list[EntryPoint]
    ) -> InvestigationTask:
        return InvestigationTask(
            scan_id=scan_id,
            task_type=TaskType.DEEP_LINK.value,
            priority=98,
            target_entry_ids=[entry.id for entry in deep_links],
            hypotheses=self._deep_link_hypotheses(owner),
            **self._base(),
        )

    @staticmethod
    def _deep_link_hypotheses(owner: str) -> list[str]:
        return [
            f"Deep links handled by {owner} are reachable from an untrusted application.",
            (
                "URI parameters, callback provenance, transaction state or nonce, encoding, and "
                "duplicate values are not strictly bound to the initiating trusted flow."
            ),
            (
                "A link can reach privileged behavior, nested intents, file access, WebView "
                "script, an internal component, or an open redirect."
            ),
        ]

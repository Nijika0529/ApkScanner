from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .enums import EntryPointKind, TaskStatus, TaskType
from .models import EntryPoint, InvestigationTask

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


class InvestigationPlanner:
    def __init__(
        self,
        *,
        android_version: str,
        adb_configured: bool,
        android_api: int = 36,
        device_reset_policy: str = "never",
    ):
        self.android_version = android_version
        self.android_api = android_api
        self.adb_configured = adb_configured
        self.device_reset_policy = device_reset_policy

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
        return plan

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
            "install_probe_apk",
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

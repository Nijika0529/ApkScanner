from __future__ import annotations

from collections import defaultdict

from .enums import EntryPointKind, TaskStatus, TaskType
from .models import EntryPoint, InvestigationTask


class InvestigationPlanner:
    def __init__(self, *, android_version: str, adb_configured: bool):
        self.android_version = android_version
        self.adb_configured = adb_configured

    def plan(self, scan_id: str, entries: list[EntryPoint]) -> list[InvestigationTask]:
        tasks: list[InvestigationTask] = []
        deep_links_by_owner: dict[str, list[EntryPoint]] = defaultdict(list)
        for entry in entries:
            if entry.kind == EntryPointKind.DEEP_LINK.value:
                deep_links_by_owner[entry.owner_component or entry.name].append(entry)
                continue
            if not entry.exported:
                continue
            tasks.append(self._component_task(scan_id, entry))
        for owner, deep_links in deep_links_by_owner.items():
            tasks.append(self._deep_link_task(scan_id, owner, deep_links))
        return tasks

    def _base(self) -> dict:
        return {
            "status": TaskStatus.QUEUED.value,
            "preconditions": {
                "guest_first": True,
                "authenticated_second": True,
                "auth_profile": "default-single-account",
            },
            "allowed_side_effects": [
                "install_target_apk",
                "install_probe_apk",
                "clear_application_data",
                "test_backend_mutations_with_cleanup",
                "root_and_frida_observation",
            ],
            "device_profile": {
                "android_version": self.android_version,
                "root_capable": True,
                "reset_capability": "pm_clear_only",
                "configured": self.adb_configured,
            },
        }

    def _component_task(self, scan_id: str, entry: EntryPoint) -> InvestigationTask:
        hypotheses = {
            EntryPointKind.ACTIVITY.value: [
                "A third-party application can launch the activity.",
                "External extras or data can bypass authentication or reach a sensitive screen.",
                "Nested intents, URI grants, or WebView navigation can cross a trust boundary.",
            ],
            EntryPointKind.ACTIVITY_ALIAS.value: [
                "The alias exposes its target activity under weaker authorization controls.",
                "Intent data or extras reach sensitive target behavior.",
            ],
            EntryPointKind.SERVICE.value: [
                "A third-party application can start or bind to the service.",
                "The service performs or returns sensitive behavior without caller authorization.",
            ],
            EntryPointKind.RECEIVER.value: [
                "An untrusted application can deliver a broadcast to the receiver.",
                "Attacker-controlled extras trigger a sensitive or persistent side effect.",
            ],
            EntryPointKind.PROVIDER.value: [
                "An untrusted application can query or open provider data.",
                "Provider paths, selections, or URI grants expose data or permit injection.",
            ],
        }[entry.kind]
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

    def _deep_link_task(
        self, scan_id: str, owner: str, deep_links: list[EntryPoint]
    ) -> InvestigationTask:
        return InvestigationTask(
            scan_id=scan_id,
            task_type=TaskType.DEEP_LINK.value,
            priority=98,
            target_entry_ids=[entry.id for entry in deep_links],
            hypotheses=[
                f"Deep links handled by {owner} are reachable from an untrusted application.",
                "URI path, query, fragment, encoding, and duplicate parameters are not strictly validated.",
                "Guest and authenticated states expose different privileged behavior.",
                "App Link verification, redirects, or custom schemes allow link interception.",
                "A link can reach nested intents, file access, WebView script, or an open redirect.",
            ],
            **self._base(),
        )

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..core.schemas import AgentRequestedTest

PLATFORM_HARNESS_GENERATOR = "ephemeral_android_app.v1"
AGENT_SOURCE_GENERATOR = "agent_android_project.v1"
DYNAMIC_EXPERIMENT_GENERATOR = "dynamic_experiment.v1"


class ProofRecipe(BaseModel):
    """Version-portable description of a platform proof experiment.

    Scan-local hypothesis and entry IDs are deliberately excluded from the
    request template.  A version replay binds those identities again and either
    regenerates the platform Harness or restores the archived Agent project.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    execution_mode: Literal["platform_harness", "agent_source", "dynamic_experiment"]
    generator: Literal[
        "ephemeral_android_app.v1",
        "agent_android_project.v1",
        "dynamic_experiment.v1",
    ]
    request_template: dict[str, Any]
    source_archive_required: bool
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_contract(self) -> ProofRecipe:
        template = dict(self.request_template)
        if "hypothesis_id" in template or "entry_point_id" in template:
            raise ValueError("ProofRecipe request_template cannot contain scan-local IDs")
        has_poc = isinstance(template.get("poc"), dict)
        has_experiment = isinstance(template.get("experiment"), dict)
        if self.execution_mode == "platform_harness" and has_poc:
            raise ValueError("platform Harness recipes cannot contain Agent PoC source")
        if self.execution_mode == "agent_source" and not has_poc:
            raise ValueError("Agent source recipes require a PoC specification")
        if self.execution_mode == "dynamic_experiment" and not has_experiment:
            raise ValueError("dynamic experiment recipes require an experiment plan")
        if self.execution_mode != "dynamic_experiment" and has_experiment:
            raise ValueError("only dynamic experiment recipes may contain an experiment plan")
        if self.execution_mode == "dynamic_experiment" and has_poc:
            raise ValueError("dynamic experiment recipes cannot contain Agent PoC source")
        if self.source_archive_required != (self.execution_mode == "agent_source"):
            raise ValueError("source_archive_required conflicts with execution_mode")
        expected = _recipe_fingerprint(
            execution_mode=self.execution_mode,
            generator=self.generator,
            request_template=template,
        )
        if self.fingerprint != expected:
            raise ValueError("ProofRecipe fingerprint does not match its request template")
        return self


def _recipe_fingerprint(
    *,
    execution_mode: str,
    generator: str,
    request_template: dict[str, Any],
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "schema_version": "1.0",
                "execution_mode": execution_mode,
                "generator": generator,
                "request_template": request_template,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def proof_recipe_for_request(request: AgentRequestedTest) -> ProofRecipe:
    template = request.model_dump(mode="json")
    template.pop("hypothesis_id", None)
    template.pop("entry_point_id", None)
    execution_mode = (
        "dynamic_experiment"
        if request.experiment is not None
        else "platform_harness"
        if request.poc is None
        else "agent_source"
    )
    generator = (
        DYNAMIC_EXPERIMENT_GENERATOR
        if execution_mode == "dynamic_experiment"
        else PLATFORM_HARNESS_GENERATOR
        if execution_mode == "platform_harness"
        else AGENT_SOURCE_GENERATOR
    )
    return ProofRecipe(
        execution_mode=execution_mode,
        generator=generator,
        request_template=template,
        source_archive_required=execution_mode == "agent_source",
        fingerprint=_recipe_fingerprint(
            execution_mode=execution_mode,
            generator=generator,
            request_template=template,
        ),
    )


def proof_recipe_from_plan(plan: dict[str, Any] | None) -> ProofRecipe | None:
    payload = dict(plan or {})
    persisted = payload.pop("proof_recipe", None)
    if isinstance(persisted, dict):
        try:
            return ProofRecipe.model_validate(persisted)
        except ValueError:
            # A malformed persisted recipe must not block a legacy plan that is
            # still independently valid and can be normalized below.
            pass
    try:
        request = AgentRequestedTest.model_validate(payload)
    except ValueError:
        return None
    return proof_recipe_for_request(request)


def bind_proof_recipe(
    recipe: ProofRecipe,
    *,
    hypothesis_id: str,
    entry_point_id: str,
    project_path: str | None = None,
    substitutions: dict[str, str] | None = None,
) -> AgentRequestedTest:
    payload = deepcopy(recipe.request_template)
    if substitutions:
        payload = _replace_strings(payload, substitutions)
    payload["hypothesis_id"] = hypothesis_id
    payload["entry_point_id"] = entry_point_id
    if recipe.execution_mode == "agent_source":
        poc = dict(payload.get("poc") or {})
        if not project_path:
            raise ValueError("Agent source ProofRecipe requires a migrated project path")
        poc["project_path"] = project_path
        poc.pop("prebuilt_apk_path", None)
        payload["poc"] = poc
    else:
        payload["poc"] = None
    payload["rationale"] = (
        "自动按 ProofRecipe 在当前版本重新生成并执行验证；结果只作为当前版本的新证据。"
    )
    return AgentRequestedTest.model_validate(payload)


def plan_with_proof_recipe(request: AgentRequestedTest) -> dict[str, Any]:
    payload = request.model_dump(mode="json")
    payload["proof_recipe"] = proof_recipe_for_request(request).model_dump(mode="json")
    return payload


def _replace_strings(value: Any, substitutions: dict[str, str]) -> Any:
    if isinstance(value, str):
        for old, new in substitutions.items():
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_replace_strings(item, substitutions) for item in value]
    if isinstance(value, dict):
        return {key: _replace_strings(item, substitutions) for key, item in value.items()}
    return value

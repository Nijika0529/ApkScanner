from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LoopDirective(StrEnum):
    EXECUTE = "execute"
    STOP = "stop"


class LoopStopReason(StrEnum):
    PROOF_COMPLETE = "proof_complete"
    RESULT_UNAVAILABLE = "result_unavailable"
    NO_PENDING_ACTION = "no_pending_action"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_PROGRESS = "no_progress"


@dataclass(frozen=True, slots=True)
class InvestigationLoopState:
    """Platform facts used to decide whether another investigation round may run."""

    has_result: bool
    has_pending_action: bool
    proof_complete: bool
    executor_ready: bool
    budget_expired: bool
    no_progress_rounds: int
    no_progress_limit: int


@dataclass(frozen=True, slots=True)
class InvestigationLoopDecision:
    directive: LoopDirective
    reason: LoopStopReason | None = None

    @property
    def should_execute(self) -> bool:
        return self.directive == LoopDirective.EXECUTE


def decide_investigation_loop(state: InvestigationLoopState) -> InvestigationLoopDecision:
    """Choose the next platform action without consulting model prose."""

    if state.proof_complete:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.PROOF_COMPLETE)
    if not state.has_result:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.RESULT_UNAVAILABLE)
    if not state.has_pending_action:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.NO_PENDING_ACTION)
    if not state.executor_ready:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.EXECUTOR_UNAVAILABLE)
    if state.budget_expired:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.BUDGET_EXHAUSTED)
    if state.no_progress_rounds >= state.no_progress_limit:
        return InvestigationLoopDecision(LoopDirective.STOP, LoopStopReason.NO_PROGRESS)
    return InvestigationLoopDecision(LoopDirective.EXECUTE)

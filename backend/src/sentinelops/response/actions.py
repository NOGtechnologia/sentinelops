"""Response actions and their state machine (spec 9).

``proposed -> approved | rejected | cancelled``;
``approved -> executed | failed | cancelled``. Nothing else is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import format_timestamp


class ActionStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TRANSITIONS: dict[ActionStatus, frozenset[ActionStatus]] = {
    ActionStatus.PROPOSED: frozenset({ActionStatus.APPROVED, ActionStatus.REJECTED, ActionStatus.CANCELLED}),
    ActionStatus.APPROVED: frozenset({ActionStatus.EXECUTED, ActionStatus.FAILED, ActionStatus.CANCELLED}),
    ActionStatus.REJECTED: frozenset(),
    ActionStatus.EXECUTED: frozenset(),
    ActionStatus.FAILED: frozenset(),
    ActionStatus.CANCELLED: frozenset(),
}


class InvalidTransitionError(ValueError):
    pass


@dataclass(frozen=True)
class Action:
    action_id: str
    case_id: str
    step_id: str
    parameters: dict[str, str]
    proposed_by: str
    proposed_at: datetime
    source: str  # analyst | playbook | ai
    reason: str
    status: ActionStatus = ActionStatus.PROPOSED

    @property
    def parameters_hash(self) -> str:
        return stable_hash("action-parameters", self.step_id, self.parameters, length=64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "case_id": self.case_id,
            "step_id": self.step_id,
            "parameters": dict(sorted(self.parameters.items())),
            "proposed_by": self.proposed_by,
            "proposed_at": format_timestamp(self.proposed_at),
            "source": self.source,
            "reason": self.reason,
            "status": self.status.value,
        }


def propose(
    case_id: str,
    step_id: str,
    parameters: dict[str, str],
    proposed_by: str,
    proposed_at: datetime,
    source: str,
    reason: str,
    response_steps: frozenset[str],
) -> Action:
    """Create a proposal. Only catalogue steps marked as response actions qualify."""
    if step_id not in response_steps:
        raise ValueError(f"{step_id} is not a response action of the playbook catalogue")
    if source not in ("analyst", "playbook", "ai"):
        raise ValueError(f"invalid source {source!r}")
    if not reason.strip():
        raise ValueError("a reason is required")
    action_id = stable_hash("action", case_id, step_id, parameters, proposed_by, format_timestamp(proposed_at))
    return Action(action_id, case_id, step_id, dict(parameters), proposed_by, proposed_at, source, reason)


def transition(action: Action, new_status: ActionStatus) -> Action:
    if new_status not in TRANSITIONS[action.status]:
        raise InvalidTransitionError(f"{action.status.value} -> {new_status.value} is not allowed")
    return replace(action, status=new_status)

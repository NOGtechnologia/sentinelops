"""Approvals and the only path to execution (spec 9).

An approval record is signed with an HMAC over the action id, the step, the
*hash of the action parameters*, the decision, the approver and the time.
:func:`execute` refuses to run anything without a valid, unchanged approval:
a changed parameter, a forged/rejected/foreign approval, a missing role or a
four-eyes violation all raise :class:`ApprovalError` before the connector is
touched.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sentinelops.normalize.schema import format_timestamp
from sentinelops.response.actions import Action, ActionStatus, transition

APPROVER_ROLE = "senior_analyst"
MIN_SECRET_BYTES = 32


class ApprovalError(PermissionError):
    pass


@dataclass(frozen=True)
class Approval:
    action_id: str
    parameters_hash: str
    decision: str  # approved | rejected
    approver: str
    reason: str
    decided_at: datetime
    signature: str

    def payload(self) -> bytes:
        return _payload(
            self.action_id, self.parameters_hash, self.decision, self.approver, self.reason, self.decided_at
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "parameters_hash": self.parameters_hash,
            "decision": self.decision,
            "approver": self.approver,
            "reason": self.reason,
            "decided_at": format_timestamp(self.decided_at),
            "signature": self.signature,
        }


def _payload(action_id: str, parameters_hash: str, decision: str, approver: str, reason: str, at: datetime) -> bytes:
    data = [action_id, parameters_hash, decision, approver, reason, format_timestamp(at)]
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(secret: bytes, payload: bytes) -> str:
    if len(secret) < MIN_SECRET_BYTES:
        raise ApprovalError("approval secret is missing or too short")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def decide(
    action: Action,
    decision: str,
    approver: str,
    approver_roles: Iterable[str],
    reason: str,
    decided_at: datetime,
    secret: bytes,
    four_eyes: bool,
) -> tuple[Action, Approval]:
    """Approve or reject a proposed action (role check, mandatory reason, four eyes)."""
    if decision not in ("approved", "rejected"):
        raise ApprovalError(f"invalid decision {decision!r}")
    if APPROVER_ROLE not in set(approver_roles):
        raise ApprovalError(f"role {APPROVER_ROLE} required to decide on actions")
    if not reason.strip():
        raise ApprovalError("a reason is required")
    if four_eyes and approver == action.proposed_by:
        raise ApprovalError("four-eyes principle: the proposer cannot decide on their own proposal")
    if action.status is not ActionStatus.PROPOSED:
        raise ApprovalError(f"action is {action.status.value}, not proposed")
    payload = _payload(action.action_id, action.parameters_hash, decision, approver, reason, decided_at)
    approval = Approval(
        action.action_id, action.parameters_hash, decision, approver, reason, decided_at, _sign(secret, payload)
    )
    new_status = ActionStatus.APPROVED if decision == "approved" else ActionStatus.REJECTED
    return transition(action, new_status), approval


def verify(action: Action, approval: Approval | None, secret: bytes, four_eyes: bool) -> None:
    """Raise unless ``approval`` is a valid, unchanged approval of ``action``."""
    if approval is None:
        raise ApprovalError("no approval")
    if approval.action_id != action.action_id:
        raise ApprovalError("approval belongs to another action")
    if approval.decision != "approved":
        raise ApprovalError("action was not approved")
    if approval.parameters_hash != action.parameters_hash:
        raise ApprovalError("action parameters changed after approval")
    if four_eyes and approval.approver == action.proposed_by:
        raise ApprovalError("four-eyes principle violated")
    expected = _sign(secret, approval.payload())
    if not hmac.compare_digest(expected, approval.signature):
        raise ApprovalError("approval signature invalid")
    if action.status is not ActionStatus.APPROVED:
        raise ApprovalError(f"action is {action.status.value}, not approved")


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    connector: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {"success": self.success, "connector": self.connector, "details": self.details}


class ResponseConnector(Protocol):
    name: str

    def run(self, action: Action) -> ExecutionResult: ...


def execute(
    action: Action, approval: Approval | None, connector: ResponseConnector, secret: bytes, four_eyes: bool
) -> tuple[Action, ExecutionResult]:
    """The single entry point to run a measure - verification first, always."""
    verify(action, approval, secret, four_eyes)
    result = connector.run(action)
    return transition(action, ActionStatus.EXECUTED if result.success else ActionStatus.FAILED), result

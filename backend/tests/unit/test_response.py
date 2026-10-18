from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sentinelops.response.actions import (
    Action,
    ActionStatus,
    InvalidTransitionError,
    propose,
    transition,
)
from sentinelops.response.approvals import Approval, ApprovalError, decide, execute, verify
from sentinelops.response.connectors.simulation import SimulationConnector
from tests.conftest import T0

SECRET = b"s" * 32
STEPS = frozenset({"DISABLE_ACCOUNT", "ISOLATE_HOST", "BLOCK_SOURCE_IP", "RESET_PASSWORD"})
SENIOR = ("analyst", "senior_analyst")


def proposal(step: str = "DISABLE_ACCOUNT", params: dict[str, str] | None = None) -> Action:
    return propose(
        "CASE-1", step, params or {"user": "jonas.becker"}, "analyst.one", T0, "analyst", "brute force success", STEPS
    )


def approved(four_eyes: bool = True) -> tuple[Action, Approval]:
    return decide(
        proposal(),
        "approved",
        "senior.two",
        SENIOR,
        "confirmed with owner",
        T0 + timedelta(minutes=5),
        SECRET,
        four_eyes,
    )


def test_happy_path_simulated_execution() -> None:
    action, approval = approved()
    assert action.status is ActionStatus.APPROVED
    done, result = execute(action, approval, SimulationConnector(), SECRET, four_eyes=True)
    assert done.status is ActionStatus.EXECUTED
    assert result.success
    assert "nothing was changed" in result.details
    assert "jonas.becker" in result.details
    assert result.to_dict()["connector"] == "simulation"
    assert approval.to_dict()["decision"] == "approved"
    assert done.to_dict()["status"] == "executed"


def test_no_execution_without_approval() -> None:
    with pytest.raises(ApprovalError, match="no approval"):
        execute(proposal(), None, SimulationConnector(), SECRET, True)


def test_proposed_action_with_foreign_approval_rejected() -> None:
    _, approval = approved()
    other = proposal(params={"user": "anna.schmidt"})
    with pytest.raises(ApprovalError, match="another action"):
        execute(other, approval, SimulationConnector(), SECRET, True)


def test_changed_parameters_invalidate_approval() -> None:
    action, approval = approved()
    tampered = replace(action, parameters={"user": "adm-mueller"})
    with pytest.raises(ApprovalError, match="parameters changed"):
        execute(tampered, approval, SimulationConnector(), SECRET, True)


def test_forged_signature_and_wrong_secret() -> None:
    action, approval = approved()
    with pytest.raises(ApprovalError, match="signature"):
        verify(action, replace(approval, signature="0" * 64), SECRET, True)
    with pytest.raises(ApprovalError, match="signature"):
        verify(action, approval, b"x" * 32, True)
    with pytest.raises(ApprovalError, match="signature"):
        verify(action, replace(approval, reason="other"), SECRET, True)


def test_rejected_decision_cannot_execute() -> None:
    action, approval = decide(proposal(), "rejected", "senior.two", SENIOR, "false positive", T0, SECRET, True)
    assert action.status is ActionStatus.REJECTED
    with pytest.raises(ApprovalError, match="not approved"):
        execute(action, approval, SimulationConnector(), SECRET, True)


def test_status_must_be_approved() -> None:
    action, approval = approved()
    with pytest.raises(ApprovalError, match="not approved"):
        verify(replace(action, status=ActionStatus.CANCELLED), approval, SECRET, True)


def test_four_eyes() -> None:
    with pytest.raises(ApprovalError, match="four-eyes"):
        decide(proposal(), "approved", "analyst.one", SENIOR, "ok", T0, SECRET, True)
    action, approval = decide(proposal(), "approved", "analyst.one", SENIOR, "ok", T0, SECRET, False)
    assert action.status is ActionStatus.APPROVED
    with pytest.raises(ApprovalError, match="four-eyes"):
        verify(action, approval, SECRET, True)
    verify(action, approval, SECRET, False)


def test_decide_requires_role_reason_valid_decision_and_state() -> None:
    with pytest.raises(ApprovalError, match="role"):
        decide(proposal(), "approved", "x", ("analyst",), "ok", T0, SECRET, True)
    with pytest.raises(ApprovalError, match="reason"):
        decide(proposal(), "approved", "x", SENIOR, " ", T0, SECRET, True)
    with pytest.raises(ApprovalError, match="invalid decision"):
        decide(proposal(), "maybe", "x", SENIOR, "ok", T0, SECRET, True)
    action, _ = approved()
    with pytest.raises(ApprovalError, match="not proposed"):
        decide(action, "approved", "x", SENIOR, "ok", T0, SECRET, True)
    with pytest.raises(ApprovalError, match="secret"):
        decide(proposal(), "approved", "x", SENIOR, "ok", T0, b"short", True)


def test_proposal_validation() -> None:
    with pytest.raises(ValueError, match="response action"):
        propose("C", "VERIFY_ACCOUNT_ACTIVITY", {}, "a", T0, "analyst", "r", STEPS)
    with pytest.raises(ValueError, match="source"):
        propose("C", "DISABLE_ACCOUNT", {}, "a", T0, "robot", "r", STEPS)
    with pytest.raises(ValueError, match="reason"):
        propose("C", "DISABLE_ACCOUNT", {}, "a", T0, "ai", "", STEPS)
    assert proposal().action_id == proposal().action_id


def test_state_machine() -> None:
    action = proposal()
    with pytest.raises(InvalidTransitionError):
        transition(action, ActionStatus.EXECUTED)
    cancelled = transition(action, ActionStatus.CANCELLED)
    with pytest.raises(InvalidTransitionError):
        transition(cancelled, ActionStatus.APPROVED)


def test_simulation_failures() -> None:
    connector = SimulationConnector()
    missing = replace(proposal(), parameters={})
    assert not connector.run(missing).success
    unknown = replace(proposal(), step_id="FORMAT_DISK")
    assert not connector.run(unknown).success
    for step, params in (
        ("ISOLATE_HOST", {"host": "ws-1"}),
        ("BLOCK_SOURCE_IP", {"ip": "203.0.113.5"}),
        ("RESET_PASSWORD", {"user": "x"}),
    ):
        assert connector.run(proposal(step, params)).success


def test_failed_connector_marks_failed() -> None:
    action, approval = decide(
        proposal("ISOLATE_HOST", {"user": "x"}), "approved", "senior.two", SENIOR, "ok", T0, SECRET, True
    )
    done, result = execute(action, approval, SimulationConnector(), SECRET, True)
    assert not result.success
    assert done.status is ActionStatus.FAILED


@settings(max_examples=100, deadline=None)
@given(
    st.dictionaries(st.sampled_from(["user", "host", "ip"]), st.text(min_size=1, max_size=20), min_size=1),
    st.sampled_from(["parameters", "signature", "decision", "approver", "action", "status", "none"]),
)
def test_property_no_execution_without_valid_unchanged_approval(params: dict[str, str], tamper: str) -> None:
    action = propose("C", "DISABLE_ACCOUNT", params, "p", T0, "analyst", "r", STEPS)
    action, approval = decide(action, "approved", "senior", SENIOR, "ok", T0, SECRET, True)
    candidate_action, candidate_approval = action, approval
    if tamper == "parameters":
        candidate_action = replace(action, parameters={**params, "user": params.get("user", "") + "x"})
    elif tamper == "signature":
        candidate_approval = replace(approval, signature=approval.signature[::-1])
    elif tamper == "decision":
        candidate_approval = replace(approval, decision="rejected")
    elif tamper == "approver":
        candidate_approval = replace(approval, approver="p")
    elif tamper == "action":
        candidate_action = replace(action, action_id="other")
    elif tamper == "status":
        candidate_action = replace(action, status=ActionStatus.PROPOSED)
    else:
        candidate_approval = None
    with pytest.raises(ApprovalError):
        execute(candidate_action, candidate_approval, SimulationConnector(), SECRET, True)

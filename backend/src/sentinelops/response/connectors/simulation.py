"""Simulation connector - the only connector in V1 (spec 9).

It changes nothing anywhere; it records precisely what a real connector
would have done.
"""

from __future__ import annotations

from sentinelops.response.actions import Action
from sentinelops.response.approvals import ExecutionResult

_TEMPLATES = {
    "DISABLE_ACCOUNT": "would disable account {user} in the directory service",
    "RESET_PASSWORD": "would reset the password of {user} and revoke its sessions",
    "ISOLATE_HOST": "would isolate host {host} via EDR network containment",
    "BLOCK_SOURCE_IP": "would block {ip} on the perimeter firewall and VPN/RDP gateway",
}


class SimulationConnector:
    name = "simulation"

    def run(self, action: Action) -> ExecutionResult:
        template = _TEMPLATES.get(action.step_id)
        if template is None:
            return ExecutionResult(False, self.name, f"SIMULATION: no simulation for {action.step_id}")
        try:
            text = template.format(**action.parameters)
        except KeyError as exc:
            return ExecutionResult(False, self.name, f"SIMULATION: parameter {exc.args[0]} missing")
        return ExecutionResult(True, self.name, f"SIMULATION (nothing was changed): {text}")

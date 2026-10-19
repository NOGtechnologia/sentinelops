"""Rule validation must work offline (read-only container, no internet).

pySigma's ATT&CK and D3FEND tag validators download MITRE data on first use and cache it under
``~/.cache``. In the hardened container that crashed ``sentinelops demo-load`` (read-only file system)
and it would make the product depend on internet access. Both validators are therefore excluded.
"""

from __future__ import annotations

import pytest
from sigma.validators.core.tags import ATTACKTagValidator, D3FENDTagValidator

from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.sigma_loader import VALIDATOR_EXCLUSIONS, load_ruleset
from sentinelops.investigation.catalog import catalog_ids
from sentinelops.settings import RULES_DIR


def _no_download(self: object) -> set[str]:
    raise AssertionError("rule validation tried to load MITRE data from the internet")


def test_rule_validation_needs_no_mitre_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ATTACKTagValidator, "_load_allowed_tags", _no_download)
    monkeypatch.setattr(D3FENDTagValidator, "_load_allowed_tags", _no_download)
    ruleset = load_ruleset(RULES_DIR, DetectionConfig(), catalog_ids())
    assert ruleset.base_rules


def test_network_validators_are_excluded() -> None:
    assert {"attacktag", "d3_fendtag"} <= VALIDATOR_EXCLUSIONS

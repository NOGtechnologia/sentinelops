"""Optional pseudonymisation before sending data to a cloud model (spec 8.2).

User names, host names and IP addresses in the evidence package are replaced
by stable placeholders (``USER_1``, ``HOST_1``, ``IP_1``) and translated back
in the model output. The mapping is deterministic (order of first appearance
in the package).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_USER_FIELDS = ("user.name", "user.target.name")
_HOST_FIELDS = ("host.name", "source.host")
_IP_FIELDS = ("source.ip",)


@dataclass
class Pseudonymizer:
    forward: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def _token(self, kind: str, value: str) -> str:
        if value not in self.forward:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.forward[value] = f"{kind}_{self.counters[kind]}"
        return self.forward[value]

    def collect(self, package: dict[str, Any]) -> None:
        for item in package.get("evidence", []):
            fields = item.get("fields", {})
            for name in _USER_FIELDS:
                if isinstance(fields.get(name), str):
                    self._token("USER", fields[name])
            for name in _HOST_FIELDS:
                if isinstance(fields.get(name), str):
                    self._token("HOST", fields[name])
            for name in _IP_FIELDS:
                if isinstance(fields.get(name), str):
                    self._token("IP", fields[name])
        for entity in package.get("entities", []):
            kind = {"user": "USER", "host": "HOST", "ip": "IP"}.get(entity.get("type", ""))
            if kind and isinstance(entity.get("display"), str):
                self._token(kind, entity["display"])

    def _pattern(self, mapping: dict[str, str]) -> re.Pattern[str] | None:
        if not mapping:
            return None
        keys = sorted(mapping, key=len, reverse=True)
        # Whole tokens only: "203.0.113.5" must not match inside "203.0.113.50"
        # and a user "name" must not match inside the key "user.name".
        alternatives = "|".join(re.escape(k) for k in keys)
        return re.compile(rf"(?<![\w.@\\-])(?:{alternatives})(?![\w@-]|\.\w)", re.IGNORECASE)

    def apply(self, text: str) -> str:
        lowered = {k.casefold(): v for k, v in self.forward.items()}
        pattern = self._pattern(self.forward)
        if pattern is None:
            return text
        return pattern.sub(lambda m: lowered[m.group(0).casefold()], text)

    def revert(self, text: str) -> str:
        backward = {v: k for k, v in self.forward.items()}
        pattern = re.compile(r"\b(?:USER|HOST|IP)_\d+\b")
        return pattern.sub(lambda m: backward.get(m.group(0), m.group(0)), text)

    def pseudonymize_package(self, package: dict[str, Any]) -> dict[str, Any]:
        self.collect(package)
        result: dict[str, Any] = json.loads(self.apply(json.dumps(package, ensure_ascii=False)))
        return result

    def revert_output(self, output: Any) -> Any:
        if isinstance(output, str):
            return self.revert(output)
        if isinstance(output, list):
            return [self.revert_output(v) for v in output]
        if isinstance(output, dict):
            return {k: self.revert_output(v) for k, v in output.items()}
        return output

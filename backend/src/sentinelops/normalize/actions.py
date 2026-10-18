"""Catalogue of normalised ``event.action`` values and their ECS categorisation.

Windows and Linux parsers map their native events onto these actions; JSON
mapping profiles may only use actions from this catalogue (validated on load).
"""

from __future__ import annotations

ACTION_META: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "logon": (("authentication",), ("start",)),
    "logon-failed": (("authentication",), ("start",)),
    "logoff": (("authentication",), ("end",)),
    "explicit-credential-logon": (("authentication",), ("start",)),
    "special-privileges-assigned": (("iam",), ("admin",)),
    "user-created": (("iam",), ("user", "creation")),
    "user-enabled": (("iam",), ("user", "change")),
    "password-reset": (("iam",), ("user", "change")),
    "password-changed": (("iam",), ("user", "change")),
    "user-deleted": (("iam",), ("user", "deletion")),
    "user-added-to-group": (("iam",), ("group", "change")),
    "group-created": (("iam",), ("group", "creation")),
    "group-deleted": (("iam",), ("group", "deletion")),
    "account-locked": (("iam",), ("user", "change")),
    "kerberos-tgt-request": (("authentication",), ("start",)),
    "kerberos-preauth-failed": (("authentication",), ("start",)),
    "ntlm-validation": (("authentication",), ("start",)),
    "audit-log-cleared": (("configuration",), ("deletion",)),
    "invalid-user": (("authentication",), ("info",)),
    "connection-closed": (("network",), ("end",)),
    "pam-auth-failure": (("authentication",), ("info",)),
    "session-opened": (("session",), ("start",)),
    "sudo-exec": (("process",), ("start",)),
    "sudo-failed": (("process",), ("start",)),
    "sudo-denied": (("process",), ("start",)),
    "su": (("authentication",), ("start",)),
    "su-failed": (("authentication",), ("start",)),
    "process-start": (("process",), ("start",)),
}

#: Actions that represent an authentication attempt (used by baselines).
LOGON_ACTIONS = frozenset({"logon", "logon-failed"})

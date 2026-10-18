"""Named, tested patterns for Linux authentication messages (spec 5.2).

Every pattern is a small, anchored regular expression with named groups and
carries example lines that double as unit tests (``tests/unit/test_linux_auth``).
Message formats were taken from the upstream sources (OpenSSH ``auth.c``,
sudo ``logging.c``, util-linux/shadow ``su``/``useradd``/``usermod``/``userdel``/
``groupadd``/``gpasswd``, Linux-PAM ``pam_unix``), see ``docs/data-sources.md``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinelops.normalize.identities import canonical_ip
from sentinelops.normalize.schema import Outcome

FieldBuilder = Callable[[dict[str, str]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class AuthPattern:
    name: str
    programs: tuple[str, ...]
    regex: re.Pattern[str]
    action: str
    outcome: Outcome
    category: tuple[str, ...]
    type: tuple[str, ...]
    build: FieldBuilder
    examples: tuple[str, ...] = field(default_factory=tuple)


def _ip_port(groups: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    ip = canonical_ip(groups.get("ip"))
    if ip:
        out["source.ip"] = ip
    elif groups.get("ip"):
        out["source.host"] = groups["ip"]
    port = groups.get("port")
    if port and port.isdigit():
        out["source.port"] = int(port)
    return out


def _ssh(groups: dict[str, str]) -> dict[str, Any]:
    out = _ip_port(groups)
    out["user.name"] = groups["user"]
    if groups.get("method"):
        out["auth.method"] = groups["method"]
    return out


def _sudo(groups: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {"user.name": groups["user"]}
    rest = groups.get("rest") or ""
    attrs = {
        key.strip(): value.strip() for key, _, value in (p.partition("=") for p in rest.split(" ; ")) if key.strip()
    }
    if attrs.get("USER"):
        out["user.target.name"] = attrs["USER"]
    command = attrs.get("COMMAND")
    if command:
        out["process.command_line"] = command
        out["process.name"] = command.split(" ", 1)[0].rsplit("/", 1)[-1]
    if attrs.get("TTY"):
        out["sudo.tty"] = attrs["TTY"]
    return out


def _target_user(key: str = "target") -> FieldBuilder:
    def build(groups: dict[str, str]) -> dict[str, Any]:
        return {"user.target.name": groups[key]}

    return build


def _su(groups: dict[str, str]) -> dict[str, Any]:
    return {"user.name": groups["user"], "user.target.name": groups["target"]}


def _group_add(groups: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {"user.target.name": groups["target"], "group.name": groups["group"]}
    if groups.get("actor"):
        out["user.name"] = groups["actor"]
    return out


def _pam(groups: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if groups.get("logname"):
        out["user.name"] = groups["logname"]
    if groups.get("user"):
        out["user.target.name"] = groups["user"]
        out.setdefault("user.name", groups["user"])
    rhost = groups.get("rhost")
    if rhost:
        out.update(_ip_port({"ip": rhost}))
    out["pam.service"] = groups["service"]
    return out


def _group_only(groups: dict[str, str]) -> dict[str, Any]:
    return {"group.name": groups["group"]}


_AUTH = ("authentication",)
_IAM = ("iam",)

PATTERNS: tuple[AuthPattern, ...] = (
    AuthPattern(
        "sshd_failed_password",
        ("sshd",),
        re.compile(
            r"^Failed (?P<method>password|publickey|keyboard-interactive(?:/pam)?|none) for "
            r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?"
        ),
        "logon-failed",
        Outcome.FAILURE,
        _AUTH,
        ("start",),
        _ssh,
        (
            "Failed password for root from 203.0.113.7 port 52211 ssh2",
            "Failed password for invalid user admin from 198.51.100.23 port 40022 ssh2",
        ),
    ),
    AuthPattern(
        "sshd_accepted",
        ("sshd",),
        re.compile(
            r"^Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic|hostbased) for "
            r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "logon",
        Outcome.SUCCESS,
        _AUTH,
        ("start",),
        _ssh,
        (
            "Accepted publickey for erika.muster from 10.20.1.15 port 50512 ssh2: ED25519 SHA256:AAAAexampleonly",
            "Accepted password for root from 203.0.113.7 port 52299 ssh2",
        ),
    ),
    AuthPattern(
        "sshd_invalid_user",
        ("sshd",),
        re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?$"),
        "invalid-user",
        Outcome.FAILURE,
        _AUTH,
        ("info",),
        _ssh,
        ("Invalid user oracle from 203.0.113.9 port 33870", "Invalid user  from 198.51.100.4 port 1022"),
    ),
    AuthPattern(
        "sshd_connection_closed",
        ("sshd",),
        re.compile(
            r"^(?:Connection closed|Disconnected from|Received disconnect from|Connection reset)"
            r"(?: by)?(?: (?:authenticating|invalid) user (?P<user>\S+))?(?: user (?P<user2>\S+))? "
            r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
        ),
        "connection-closed",
        Outcome.UNKNOWN,
        ("network",),
        ("end",),
        lambda g: (
            _ip_port(g) | ({"user.name": g.get("user") or g.get("user2")} if (g.get("user") or g.get("user2")) else {})
        ),
        (
            "Connection closed by 203.0.113.7 port 52211 [preauth]",
            "Disconnected from user erika.muster 10.20.1.15 port 50512",
            "Connection closed by authenticating user root 203.0.113.7 port 52211 [preauth]",
        ),
    ),
    AuthPattern(
        "pam_unix_auth_failure",
        ("sshd", "sudo", "su", "login", "passwd", "sshd-session"),
        re.compile(
            r"^pam_unix\((?P<service>[\w-]+):auth\): authentication failure; logname=(?P<logname>\S*) uid=\d+ "
            r"euid=\d+ tty=\S* ruser=\S* rhost=(?P<rhost>\S*)(?:\s+user=(?P<user>\S+))?"
        ),
        "pam-auth-failure",
        Outcome.FAILURE,
        _AUTH,
        ("info",),
        _pam,
        (
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root",
            "pam_unix(sudo:auth): authentication failure; logname=max.mustermann uid=1001 euid=0 tty=/dev/pts/0 ruser=max.mustermann rhost=  user=max.mustermann",
        ),
    ),
    AuthPattern(
        "pam_session_opened",
        ("sshd", "su", "sudo", "login", "sshd-session", "systemd", "cron", "CRON"),
        re.compile(
            r"^pam_unix\((?P<service>[\w-]+):session\): session opened for user (?P<user>[^\s(]+)"
            r"(?:\(uid=\d+\))? by (?P<logname>[^\s(]*)"
        ),
        "session-opened",
        Outcome.SUCCESS,
        ("session",),
        ("start",),
        lambda g: (
            {"user.target.name": g["user"], "pam.service": g["service"]}
            | ({"user.name": g["logname"]} if g.get("logname") else {})
        ),
        (
            "pam_unix(sshd:session): session opened for user erika.muster(uid=1004) by (uid=0)",
            "pam_unix(su:session): session opened for user root(uid=0) by max.mustermann(uid=1001)",
        ),
    ),
    AuthPattern(
        "sudo_command",
        ("sudo",),
        re.compile(r"^\s*(?P<user>\S+) : (?P<rest>TTY=.*COMMAND=.*)$"),
        "sudo-exec",
        Outcome.SUCCESS,
        ("process",),
        ("start",),
        _sudo,
        (
            "max.mustermann : TTY=pts/0 ; PWD=/home/max.mustermann ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
            "svc_deploy : PWD=/opt/app ; USER=root ; TTY=pts/1 ; COMMAND=/usr/bin/apt-get upgrade -y",
        ),
    ),
    AuthPattern(
        "sudo_failed",
        ("sudo",),
        re.compile(r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|a password is required) ; (?P<rest>.*)$"),
        "sudo-failed",
        Outcome.FAILURE,
        ("process",),
        ("start",),
        _sudo,
        (
            "max.mustermann : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/max.mustermann ; USER=root ; COMMAND=/bin/bash",
            "erika.muster : 1 incorrect password attempt ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id",
        ),
    ),
    AuthPattern(
        "sudo_denied",
        ("sudo",),
        re.compile(
            r"^\s*(?P<user>\S+) : (?:user NOT in sudoers|user NOT authorized on host|command not allowed) ; (?P<rest>.*)$"
        ),
        "sudo-denied",
        Outcome.FAILURE,
        ("process",),
        ("start",),
        _sudo,
        (
            "praktikant01 : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/praktikant01 ; USER=root ; COMMAND=/bin/su",
            "erika.muster : command not allowed ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        ),
    ),
    AuthPattern(
        "su_success",
        ("su",),
        re.compile(
            r"^(?:Successful su for (?P<target2>\S+) by (?P<user2>\S+)|\(to (?P<target>\S+)\) (?P<user>\S+) on \S+)"
        ),
        "su",
        Outcome.SUCCESS,
        _AUTH,
        ("start",),
        lambda g: {
            "user.name": g.get("user") or g.get("user2") or "",
            "user.target.name": g.get("target") or g.get("target2") or "",
        },
        ("(to root) max.mustermann on pts/0", "Successful su for root by max.mustermann"),
    ),
    AuthPattern(
        "su_failed",
        ("su",),
        re.compile(
            r"^FAILED (?:SU|su) (?:\(to (?P<target>\S+)\) (?P<user>\S+) on \S+|for (?P<target2>\S+) by (?P<user2>\S+))"
        ),
        "su-failed",
        Outcome.FAILURE,
        _AUTH,
        ("start",),
        lambda g: {
            "user.name": g.get("user") or g.get("user2") or "",
            "user.target.name": g.get("target") or g.get("target2") or "",
        },
        ("FAILED SU (to root) max.mustermann on pts/0", "FAILED su for root by erika.muster"),
    ),
    AuthPattern(
        "useradd_new_user",
        ("useradd", "adduser"),
        re.compile(r"^new user: name=(?P<target>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)"),
        "user-created",
        Outcome.SUCCESS,
        _IAM,
        ("user", "creation"),
        lambda g: {"user.target.name": g["target"], "user.target.id": g["uid"], "group.id": g["gid"]},
        (
            "new user: name=tmp.admin, UID=1050, GID=1050, home=/home/tmp.admin, shell=/bin/bash, from=/dev/pts/0",
            "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash",
        ),
    ),
    AuthPattern(
        "groupadd_new_group",
        ("useradd", "groupadd", "adduser", "addgroup"),
        re.compile(r"^(?:new group|group added to /etc/group): name=(?P<group>[^,]+), GID=(?P<gid>\d+)"),
        "group-created",
        Outcome.SUCCESS,
        _IAM,
        ("group", "creation"),
        lambda g: {"group.name": g["group"], "group.id": g["gid"]},
        ("new group: name=tmp.admin, GID=1050", "group added to /etc/group: name=devops, GID=1100"),
    ),
    AuthPattern(
        "usermod_add_group",
        ("usermod",),
        re.compile(r"^add '(?P<target>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
        "user-added-to-group",
        Outcome.SUCCESS,
        _IAM,
        ("group", "change"),
        _group_add,
        ("add 'tmp.admin' to group 'sudo'", "add 'max.mustermann' to shadow group 'wheel'"),
    ),
    AuthPattern(
        "gpasswd_add",
        ("gpasswd",),
        re.compile(r"^user (?P<target>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)"),
        "user-added-to-group",
        Outcome.SUCCESS,
        _IAM,
        ("group", "change"),
        _group_add,
        ("user tmp.admin added by root to group sudo", "user erika.muster added by max.mustermann to group docker"),
    ),
    AuthPattern(
        "userdel_delete",
        ("userdel", "deluser"),
        re.compile(r"^delete user '(?P<target>[^']+)'"),
        "user-deleted",
        Outcome.SUCCESS,
        _IAM,
        ("user", "deletion"),
        _target_user(),
        ("delete user 'tmp.admin'", "delete user 'praktikant02'"),
    ),
    AuthPattern(
        "userdel_group_removed",
        ("userdel",),
        re.compile(r"^removed group '(?P<group>[^']+)'"),
        "group-deleted",
        Outcome.SUCCESS,
        _IAM,
        ("group", "deletion"),
        _group_only,
        ("removed group 'tmp.admin' owned by 'tmp.admin'", "removed group 'devops'"),
    ),
    AuthPattern(
        "password_changed",
        ("passwd", "chpasswd", "chage", "sshd"),
        re.compile(r"^pam_unix\((?P<service>[\w-]+):chauthtok\): password changed for (?P<target>\S+)"),
        "password-changed",
        Outcome.SUCCESS,
        _IAM,
        ("user", "change"),
        lambda g: {"user.target.name": g["target"]},
        (
            "pam_unix(passwd:chauthtok): password changed for erika.muster",
            "pam_unix(chpasswd:chauthtok): password changed for svc_backup",
        ),
    ),
)

_BY_PROGRAM: dict[str, tuple[AuthPattern, ...]] = {}
for _pattern in PATTERNS:
    for _program in _pattern.programs:
        _BY_PROGRAM[_program] = (*_BY_PROGRAM.get(_program, ()), _pattern)


@dataclass(frozen=True, slots=True)
class AuthMatch:
    pattern: str
    action: str
    outcome: Outcome
    category: tuple[str, ...]
    type: tuple[str, ...]
    fields: dict[str, Any]


def match_message(program: str | None, message: str) -> AuthMatch | None:
    """Return the first matching named pattern for ``program``."""
    if not program:
        return None
    candidates = _BY_PROGRAM.get(program) or _BY_PROGRAM.get(program.rsplit("/", 1)[-1])
    if not candidates:
        return None
    for pattern in candidates:
        found = pattern.regex.match(message)
        if found is None:
            continue
        groups = {k: v for k, v in found.groupdict().items() if v is not None}
        fields = {k: v for k, v in pattern.build(groups).items() if v not in (None, "")}
        if groups.get("invalid"):
            fields["sshd.invalid_user"] = True
        return AuthMatch(pattern.name, pattern.action, pattern.outcome, pattern.category, pattern.type, fields)
    return None

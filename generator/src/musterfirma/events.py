"""Builders for Windows Security events and Linux auth messages.

Field names and orders follow the Microsoft event documentation (4624, 4625,
4634, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4768, 4776, 1102) and the
upstream message formats used by ``sentinelops.parsers.linux_auth``.
"""

from __future__ import annotations

from datetime import datetime

from musterfirma.org import DOMAIN_SID, NETBIOS
from musterfirma.records import SysRecord, WinRecord

NULL_SID = "S-1-0-0"
SYSTEM_SID = "S-1-5-18"
LOGON_PROCESS = {2: "User32 ", 3: "Kerberos", 7: "User32 ", 10: "User32 ", 11: "User32 "}


class Account:
    """A security principal as it appears in event data."""

    def __init__(self, name: str, sid: str, domain: str = NETBIOS) -> None:
        self.name = name
        self.sid = sid
        self.domain = domain

    @classmethod
    def machine(cls, host: str, rid: int = 1000) -> Account:
        return cls(f"{host.upper()}$", f"{DOMAIN_SID}-{rid}")


def _logon_id(t: datetime, salt: int) -> str:
    return hex(0x10000 + (int(t.timestamp()) * 7 + salt) % 0xFFFFF)


def logon(host: str, t: datetime, user: Account, logon_type: int, ip: str, port: int,
          workstation: str, package: str = "Kerberos", subject: Account | None = None) -> WinRecord:
    subj = subject or Account.machine(host)
    return WinRecord(host, t, 4624, {
        "SubjectUserSid": subj.sid if subject else SYSTEM_SID, "SubjectUserName": subj.name,
        "SubjectDomainName": subj.domain, "SubjectLogonId": "0x3e7",
        "TargetUserSid": user.sid, "TargetUserName": user.name, "TargetDomainName": user.domain,
        "TargetLogonId": _logon_id(t, len(user.name)), "LogonType": str(logon_type),
        "LogonProcessName": LOGON_PROCESS.get(logon_type, "Advapi  "),
        "AuthenticationPackageName": package if logon_type == 3 else "Negotiate",
        "WorkstationName": workstation.upper(), "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0" if logon_type == 3 else "0x2a4",
        "ProcessName": "-" if logon_type == 3 else "C:\\Windows\\System32\\svchost.exe",
        "IpAddress": ip, "IpPort": str(port), "ImpersonationLevel": "%%1833",
        "RestrictedAdminMode": "-", "VirtualAccount": "%%1843", "ElevatedToken": "%%1842",
    })


def logon_failed(host: str, t: datetime, user_name: str, logon_type: int, ip: str, port: int,
                 workstation: str, status: str = "0xc000006d", sub_status: str = "0xc000006a",
                 domain: str = NETBIOS) -> WinRecord:
    return WinRecord(host, t, 4625, {
        "SubjectUserSid": NULL_SID if logon_type == 3 else SYSTEM_SID,
        "SubjectUserName": "-" if logon_type == 3 else f"{host.upper()}$",
        "SubjectDomainName": "-" if logon_type == 3 else NETBIOS, "SubjectLogonId": "0x0" if logon_type == 3 else "0x3e7",
        "TargetUserSid": NULL_SID, "TargetUserName": user_name, "TargetDomainName": domain,
        "Status": status, "FailureReason": "%%2313", "SubStatus": sub_status, "LogonType": str(logon_type),
        "LogonProcessName": LOGON_PROCESS.get(logon_type, "NtLmSsp "), "AuthenticationPackageName": "NTLM" if logon_type == 3 else "Negotiate",
        "WorkstationName": workstation, "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip, "IpPort": str(port),
    })


def logoff(host: str, t: datetime, user: Account, logon_type: int) -> WinRecord:
    return WinRecord(host, t, 4634, {
        "TargetUserSid": user.sid, "TargetUserName": user.name, "TargetDomainName": user.domain,
        "TargetLogonId": _logon_id(t, len(user.name) + 1), "LogonType": str(logon_type),
    })


def special_privileges(host: str, t: datetime, user: Account) -> WinRecord:
    return WinRecord(host, t, 4672, {
        "SubjectUserSid": user.sid, "SubjectUserName": user.name, "SubjectDomainName": user.domain,
        "SubjectLogonId": _logon_id(t, 3),
        "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege",
    })


def _account_change(event_id: int, host: str, t: datetime, subject: Account, target: Account) -> WinRecord:
    data = {
        "TargetUserName": target.name, "TargetDomainName": target.domain, "TargetSid": target.sid,
        "SubjectUserSid": subject.sid, "SubjectUserName": subject.name, "SubjectDomainName": subject.domain,
        "SubjectLogonId": _logon_id(t, 5),
    }
    if event_id == 4720:
        data.update({"PrivilegeList": "-", "SamAccountName": target.name, "DisplayName": "%%1793",
                     "UserPrincipalName": f"{target.name}@musterfirma.example", "PrimaryGroupId": "513",
                     "UserAccountControl": "%%2080 %%2082 %%2084", "NewUacValue": "0x15", "OldUacValue": "0x0"})
    return WinRecord(host, t, event_id, data)


def user_created(host: str, t: datetime, subject: Account, target: Account) -> WinRecord:
    return _account_change(4720, host, t, subject, target)


def user_enabled(host: str, t: datetime, subject: Account, target: Account) -> WinRecord:
    return _account_change(4722, host, t, subject, target)


def password_reset(host: str, t: datetime, subject: Account, target: Account) -> WinRecord:
    return _account_change(4724, host, t, subject, target)


def user_deleted(host: str, t: datetime, subject: Account, target: Account) -> WinRecord:
    return _account_change(4726, host, t, subject, target)


GROUP_SIDS = {"Domain Admins": f"{DOMAIN_SID}-512", "Enterprise Admins": f"{DOMAIN_SID}-519", "Administrators": "S-1-5-32-544"}
GROUP_EVENT = {"Domain Admins": 4728, "Enterprise Admins": 4756, "Administrators": 4732}


def group_member_added(host: str, t: datetime, subject: Account, member: Account, member_display: str,
                       group: str, ou: str = "Mitarbeiter") -> WinRecord:
    event_id = GROUP_EVENT.get(group, 4728)
    group_sid = GROUP_SIDS.get(group, f"{DOMAIN_SID}-{3000 + sum(map(ord, group)) % 900}")
    return WinRecord(host, t, event_id, {
        "MemberName": f"CN={member_display},OU={ou},DC=musterfirma,DC=example", "MemberSid": member.sid,
        "TargetUserName": group, "TargetDomainName": "Builtin" if group == "Administrators" else NETBIOS,
        "TargetSid": group_sid, "SubjectUserSid": subject.sid, "SubjectUserName": subject.name,
        "SubjectDomainName": subject.domain, "SubjectLogonId": _logon_id(t, 9), "PrivilegeList": "-",
    })


def lockout(host: str, t: datetime, target: Account, caller: str) -> WinRecord:
    return WinRecord(host, t, 4740, {
        "TargetUserName": target.name, "TargetDomainName": caller.upper(), "TargetSid": target.sid,
        "SubjectUserSid": SYSTEM_SID, "SubjectUserName": f"{host.upper()}$", "SubjectDomainName": NETBIOS,
        "SubjectLogonId": "0x3e7",
    })


def tgt_request(host: str, t: datetime, user: Account, ip: str, port: int, status: str = "0x0") -> WinRecord:
    return WinRecord(host, t, 4768, {
        "TargetUserName": user.name, "TargetDomainName": NETBIOS, "TargetSid": user.sid,
        "ServiceName": "krbtgt", "ServiceSid": f"{DOMAIN_SID}-502", "TicketOptions": "0x40810010",
        "Status": status, "TicketEncryptionType": "0x12", "PreAuthType": "2",
        "IpAddress": f"::ffff:{ip}", "IpPort": str(port),
    })


def ntlm_validation(host: str, t: datetime, user_name: str, workstation: str, status: str = "0x0") -> WinRecord:
    return WinRecord(host, t, 4776, {
        "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "TargetUserName": user_name,
        "Workstation": workstation.upper(), "Status": status,
    })


def log_cleared(host: str, t: datetime, subject: Account) -> WinRecord:
    return WinRecord(host, t, 1102, {
        "SubjectUserSid": subject.sid, "SubjectUserName": subject.name, "SubjectDomainName": subject.domain,
        "SubjectLogonId": _logon_id(t, 11),
    }, provider="Microsoft-Windows-Eventlog", user_data=True)


# --- Linux -------------------------------------------------------------------

def ssh_failed(host: str, t: datetime, pid: int, user: str, ip: str, port: int, invalid: bool = False) -> SysRecord:
    who = f"invalid user {user}" if invalid else user
    return SysRecord(host, t, "sshd", pid, f"Failed password for {who} from {ip} port {port} ssh2")


def ssh_accepted(host: str, t: datetime, pid: int, user: str, ip: str, port: int, method: str = "publickey") -> SysRecord:
    suffix = ": ED25519 SHA256:exampleonlykeyfingerprint" if method == "publickey" else ""
    return SysRecord(host, t, "sshd", pid, f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}")


def ssh_invalid_user(host: str, t: datetime, pid: int, user: str, ip: str, port: int) -> SysRecord:
    return SysRecord(host, t, "sshd", pid, f"Invalid user {user} from {ip} port {port}")


def ssh_session(host: str, t: datetime, pid: int, user: str, uid: int) -> SysRecord:
    return SysRecord(host, t, "sshd", pid, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")


def ssh_disconnect(host: str, t: datetime, pid: int, user: str, ip: str, port: int) -> SysRecord:
    return SysRecord(host, t, "sshd", pid, f"Disconnected from user {user} {ip} port {port}")


def sudo_ok(host: str, t: datetime, user: str, command: str, cwd: str = "/root", target: str = "root") -> SysRecord:
    return SysRecord(host, t, "sudo", None, f"{user} : TTY=pts/0 ; PWD={cwd} ; USER={target} ; COMMAND={command}")


def sudo_failed(host: str, t: datetime, user: str, command: str, attempts: int = 3) -> SysRecord:
    noun = "attempt" if attempts == 1 else "attempts"
    return SysRecord(host, t, "sudo", None,
                     f"{user} : {attempts} incorrect password {noun} ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")


def su_failed(host: str, t: datetime, pid: int, user: str, target: str = "root") -> SysRecord:
    return SysRecord(host, t, "su", pid, f"FAILED SU (to {target}) {user} on pts/0")


def cron_session(host: str, t: datetime, pid: int) -> SysRecord:
    return SysRecord(host, t, "CRON", pid, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")

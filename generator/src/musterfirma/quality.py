"""Data quality cases (spec section 11): every broken record is labelled with
the processing status and error code SentinelOps must assign to it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Labelled:
    content: str | bytes
    status: str  # accepted | duplicate | malformed
    code: str | None = None
    flag: str | None = None  # expected quality flag for accepted records


def broken_syslog() -> list[Labelled]:
    """RFC 3164 lines: year wrap, DST switch, truncation, encoding, size."""
    return [
        Labelled("Dec 31 23:59:58 srv-lnx04 sshd[100]: Connection closed by 10.30.0.99 port 50000", "accepted"),
        Labelled("Jan  1 00:00:02 srv-lnx04 sshd[101]: Connection closed by 10.30.0.99 port 50001", "accepted"),
        # Last Sunday of March 2025: 02:30 does not exist in Europe/Berlin.
        Labelled(
            "Mar 30 02:30:00 srv-lnx04 CRON[102]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "accepted",
            flag="nonexistent_local_time",
        ),
        # Last Sunday of October 2025: 02:30 exists twice.
        Labelled(
            "Oct 26 02:30:00 srv-lnx04 CRON[103]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "accepted",
            flag="ambiguous_local_time",
        ),
        Labelled("Mar 12 09:00:00 srv-lnx04", "malformed", "TRUNCATED"),
        Labelled("srv-lnx04 sshd[104]: message without timestamp", "malformed", "MISSING_TIMESTAMP"),
        Labelled(b"Mar 12 09:00:01 srv-lnx04 sshd[105]: invalid \xff\xfe bytes", "malformed", "INVALID_ENCODING"),
        Labelled("Mar 12 09:00:02 srv-lnx04 app[106]: " + "A" * 70_000, "malformed", "OVERSIZED"),
        Labelled("<999>Mar 12 09:00:03 srv-lnx04 app[107]: bad priority", "malformed", "PARSE_ERROR"),
        Labelled("Mar 12 09:00:04 srv-lnx04 sshd[108]: Connection closed by 10.30.0.99 port 50002", "accepted"),
        Labelled("Mar 12 09:00:04 srv-lnx04 sshd[108]: Connection closed by 10.30.0.99 port 50002", "duplicate"),
    ]


_EVENT_HEAD = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>'
)


def broken_windows_xml() -> list[Labelled]:
    ok = (
        _EVENT_HEAD + '<EventID>4634</EventID><TimeCreated SystemTime="2026-03-12T08:00:00.0000000Z"/>'
        "<EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>WS-0099.musterfirma.example</Computer>"
        '</System><EventData><Data Name="TargetUserName">vera.wolf</Data><Data Name="LogonType">3</Data></EventData></Event>'
    )
    return [
        Labelled(ok, "accepted"),
        Labelled(ok, "duplicate"),
        Labelled(
            _EVENT_HEAD + "<EventID>4634</EventID><EventRecordID>2</EventRecordID><Channel>Security</Channel>"
            "<Computer>WS-0099.musterfirma.example</Computer></System><EventData/></Event>",
            "malformed",
            "MISSING_TIMESTAMP",
        ),
        Labelled(
            _EVENT_HEAD + '<EventID>four</EventID><TimeCreated SystemTime="2026-03-12T08:00:01Z"/></System></Event>',
            "malformed",
            "SCHEMA_VIOLATION",
        ),
        Labelled(
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4634</EventID'
            '><TimeCreated SystemTime="2026-03-12T08:00:02Z"/></Sys></Event>',
            "malformed",
            "PARSE_ERROR",
        ),
        Labelled(
            _EVENT_HEAD + '<EventID>4634</EventID><TimeCreated SystemTime="2026-03-12T08:00:03.0000000Z"/>'
            "<EventRecordID>3</EventRecordID><Channel>Security</Channel><Computer>WS-0099.musterfirma.example</Computer>"
            '</System><EventData><Data Name="TargetUserName">vera.wolf',
            "malformed",
            "TRUNCATED",
        ),
    ]


def broken_vpn() -> list[Labelled]:
    return [
        Labelled(
            '{"ts": 1773302400000, "seq": 900001, "gateway": "vpn01", "type": "disconnect", "result": "ok", "user": "vera.wolf"}',
            "accepted",
        ),
        Labelled(
            '{"ts": 1773302400000, "seq": 900002, "gateway": "vpn01", "type": "auth", "result": "ok", "user": ',
            "malformed",
            "TRUNCATED",
        ),
        Labelled('{"ts": 1773302400000, "seq": 900003, "gateway" "vpn01"}', "malformed", "PARSE_ERROR"),
        Labelled(
            '{"seq": 900004, "gateway": "vpn01", "type": "auth", "result": "ok", "user": "vera.wolf"}',
            "malformed",
            "MISSING_TIMESTAMP",
        ),
        Labelled(
            '{"ts": 1773302400000, "seq": 900005, "gateway": "vpn01", "x": ' + "[" * 40 + "]" * 40 + "}",
            "malformed",
            "OVERSIZED",
        ),
        Labelled(
            '{"ts": 1773302400000, "seq": 900006, "gateway": "vpn01", "client": {"ip": "not-an-ip"}}',
            "malformed",
            "SCHEMA_VIOLATION",
        ),
    ]

"""Normal behaviour of Musterfirma GmbH (spec section 11).

Work-hour logons, occasional password typos, network access to file/mail/app
servers, admin work (RDP, group changes, password resets, SSH + sudo),
service accounts (monitoring, backup, deployment), cron and a little internet
noise on the exposed web server. Volume is scaled to ``events_per_day``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta

from musterfirma import events as ev
from musterfirma.org import EXTERNAL_MISC_NET, Organisation, User
from musterfirma.records import Record, SysRecord, VpnRecord, WinRecord
from musterfirma.writers import BERLIN

FILE_SERVERS = ("srv-file01", "srv-file02", "srv-mail01", "srv-app01", "srv-print01")
ADMIN_SERVERS = ("srv-file01", "srv-file02", "srv-app01", "srv-sql01", "srv-mail01", "srv-backup01", "srv-print01")
NORMAL_COMMANDS = (
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/apt-get update",
    "/usr/bin/journalctl -u ssh",
    "/usr/bin/systemctl status app",
    "/usr/bin/tail -n 100 /var/log/syslog",
    "/usr/bin/df -h",
)


def local(day: date, hour: float) -> datetime:
    """Local Berlin wall clock (fractional hours) -> aware UTC datetime."""
    naive = datetime.combine(day, time()) + timedelta(seconds=round(hour * 3600))
    return naive.replace(tzinfo=BERLIN).astimezone(UTC)


def account(user: User) -> ev.Account:
    return ev.Account(user.name, user.sid)


def service_account(name: str, rid: int) -> ev.Account:
    return ev.Account(name, f"{ev.DOMAIN_SID}-{rid}")


SERVICE_RIDS = {"svc_backup": 1601, "svc_monitor": 1602, "svc_sql": 1603, "svc_deploy": 1604}


@dataclass
class DayContext:
    org: Organisation
    rng: random.Random
    day: date
    out: list[Record] = field(default_factory=list)
    pid: int = 3000
    port: int = 49152

    def next_pid(self) -> int:
        self.pid += self.rng.randint(1, 40)
        if self.pid > 60000:
            self.pid = 3000
        return self.pid

    def next_port(self) -> int:
        self.port += self.rng.randint(1, 30)
        if self.port > 65000:
            self.port = 49152
        return self.port

    def dc(self) -> str:
        return self.rng.choice(("dc01", "dc02"))


def _user_servers(user: User) -> tuple[str, ...]:
    return tuple(FILE_SERVERS[(user.rid + i) % len(FILE_SERVERS)] for i in range(3))


def _office_day(ctx: DayContext, user: User, start: float, end: float) -> list[tuple[datetime, str, str]]:
    """Interactive day on the user's workstation. Returns network sessions slots."""
    rng, org = ctx.rng, ctx.org
    ws = org.host_by_name(user.workstation)
    acc = account(user)
    t_logon = local(ctx.day, start)
    if rng.random() < 0.08:  # password typo(s) in the morning
        for i in range(rng.randint(1, 2)):
            ctx.out.append(
                ev.logon_failed(
                    ws.name, t_logon - timedelta(seconds=40 - i * 15), user.name, 2, "127.0.0.1", 0, ws.name.upper()
                )
            )
    ctx.out.append(ev.tgt_request(ctx.dc(), t_logon - timedelta(seconds=1), acc, ws.ip, ctx.next_port()))
    ctx.out.append(ev.logon(ws.name, t_logon, acc, 2, "127.0.0.1", 0, ws.name))
    for _ in range(rng.randint(2, 5)):
        t = local(ctx.day, rng.uniform(start + 0.5, end - 0.2))
        ctx.out.append(ev.logon(ws.name, t, acc, 7, "127.0.0.1", 0, ws.name))
    ctx.out.append(ev.logoff(ws.name, local(ctx.day, end + rng.uniform(0, 0.4)), acc, 2))
    return [(t_logon, ws.ip, s) for s in _user_servers(user)]


def _remote_day(ctx: DayContext, user: User, start: float) -> list[tuple[datetime, str, str]]:
    rng, org = ctx.rng, ctx.org
    if user.home_ip is None:
        raise ValueError(f"{user.name} has no home office address")
    t0 = local(ctx.day, start)
    vpn_ip = f"10.99.0.{(user.rid % 200) + 10}"
    ctx.out.append(
        VpnRecord(
            t0 - timedelta(minutes=2),
            "auth",
            "ok",
            f"{user.name}@musterfirma.example",
            "certificate",
            user.home_ip,
            ctx.next_port(),
        )
    )
    acc = account(user)
    if rng.random() < 0.3:  # some remote users work via the RDP gateway
        gw = org.server("srv-gw01")
        ctx.out.append(ev.logon(gw.name, t0, acc, 10, user.home_ip, ctx.next_port(), gw.name, package="Negotiate"))
        ctx.out.append(ev.logoff(gw.name, t0 + timedelta(hours=rng.uniform(3, 8)), acc, 10))
    return [(t0, vpn_ip, s) for s in _user_servers(user)]


def _network_session(ctx: DayContext, user: User, when: datetime, src_ip: str, server: str) -> None:
    acc = account(user)
    ctx.out.append(ev.logon(server, when, acc, 3, src_ip, ctx.next_port(), user.workstation))
    ctx.out.append(ev.logoff(server, when + timedelta(seconds=ctx.rng.randint(5, 900)), acc, 3))


def _admin_day(ctx: DayContext, admin: User) -> None:
    rng, org = ctx.rng, ctx.org
    acc = account(admin)
    ws = org.host_by_name(admin.workstation)
    for server in rng.sample(ADMIN_SERVERS, rng.randint(1, 3)):
        t = local(ctx.day, rng.uniform(admin.start_hour + 0.3, admin.end_hour - 1))
        ctx.out.append(ev.logon(server, t, acc, 10, ws.ip, ctx.next_port(), ws.name, package="Negotiate"))
        ctx.out.append(ev.special_privileges(server, t + timedelta(milliseconds=3), acc))
        ctx.out.append(ev.logoff(server, t + timedelta(minutes=rng.randint(5, 50)), acc, 10))
    # identity administration on the DC (non-privileged groups only)
    for _ in range(rng.randint(0, 2)):
        target = rng.choice(org.users)
        t = local(ctx.day, rng.uniform(admin.start_hour + 0.5, admin.end_hour - 0.5))
        ctx.out.append(
            ev.group_member_added("dc01", t, acc, account(target), target.display, rng.choice(org.normal_groups))
        )
    for _ in range(rng.randint(0, 2)):
        target = rng.choice(org.users)
        t = local(ctx.day, rng.uniform(admin.start_hour + 0.5, admin.end_hour - 0.5))
        ctx.out.append(ev.password_reset("dc01", t, acc, account(target)))
    # Linux administration via SSH + sudo
    for server in rng.sample([h.name for h in org.linux_servers], rng.randint(1, 2)):
        t = local(ctx.day, rng.uniform(admin.start_hour + 0.3, admin.end_hour - 0.5))
        pid = ctx.next_pid()
        port = ctx.next_port()
        ctx.out.append(ev.ssh_accepted(server, t, pid, admin.name, ws.ip, port))
        ctx.out.append(ev.ssh_session(server, t, pid, admin.name, 1000 + admin.rid % 100))
        for i in range(rng.randint(1, 3)):
            ctx.out.append(
                ev.sudo_ok(
                    server,
                    t + timedelta(minutes=1 + i),
                    admin.name,
                    rng.choice(NORMAL_COMMANDS),
                    cwd=f"/home/{admin.name}",
                )
            )
        ctx.out.append(
            ev.ssh_disconnect(server, t + timedelta(minutes=rng.randint(10, 40)), pid, admin.name, ws.ip, port)
        )


def _service_accounts(ctx: DayContext, weekend: bool) -> None:
    rng, org = ctx.rng, ctx.org
    monitor = service_account("svc_monitor", SERVICE_RIDS["svc_monitor"])
    mon_ip = org.server("srv-app01").ip
    for slot in range(0, 96):
        base = local(ctx.day, slot / 4)
        for server in org.servers:
            t = base + timedelta(seconds=rng.randint(0, 50))
            ctx.out.append(ev.logon(server.name, t, monitor, 3, mon_ip, ctx.next_port(), "SRV-APP01", package="NTLM"))
            ctx.out.append(ev.logoff(server.name, t + timedelta(seconds=2), monitor, 3))
        if slot % 2 == 0:
            for host in org.linux_servers:
                t = base + timedelta(seconds=rng.randint(0, 50))
                pid = ctx.next_pid()
                ctx.out.append(ev.ssh_accepted(host.name, t, pid, "svc_monitor", mon_ip, ctx.next_port()))
                ctx.out.append(ev.ssh_session(host.name, t, pid, "svc_monitor", 998))
    backup = service_account("svc_backup", SERVICE_RIDS["svc_backup"])
    bk_ip = org.server("srv-backup01").ip
    for server in ("srv-file01", "srv-file02", "srv-sql01", "srv-mail01"):
        t = local(ctx.day, 1.0 + rng.uniform(0, 0.5))
        ctx.out.append(ev.logon(server, t, backup, 3, bk_ip, ctx.next_port(), "SRV-BACKUP01"))
        ctx.out.append(ev.special_privileges(server, t + timedelta(milliseconds=2), backup))
        ctx.out.append(ev.logoff(server, t + timedelta(minutes=rng.randint(20, 90)), backup, 3))
    sql = service_account("svc_sql", SERVICE_RIDS["svc_sql"])
    for hour in range(24):
        t = local(ctx.day, hour + rng.uniform(0, 0.9))
        ctx.out.append(ev.logon("srv-sql01", t, sql, 3, mon_ip, ctx.next_port(), "SRV-APP01"))
        ctx.out.append(ev.logoff("srv-sql01", t + timedelta(seconds=30), sql, 3))
    for hour in range(8, 18) if not weekend else ():
        t = local(ctx.day, hour + rng.uniform(0, 0.9))
        pid = ctx.next_pid()
        ctx.out.append(ev.ssh_accepted("srv-lnx03", t, pid, "svc_deploy", mon_ip, ctx.next_port()))
        ctx.out.append(
            ev.sudo_ok(
                "srv-lnx03", t + timedelta(seconds=5), "svc_deploy", "/usr/bin/systemctl restart app", cwd="/opt/app"
            )
        )
    for host in org.linux_servers:
        for slot in range(0, 144):
            ctx.out.append(ev.cron_session(host.name, local(ctx.day, slot / 6) + timedelta(seconds=1), ctx.next_pid()))


def _internet_noise(ctx: DayContext) -> None:
    rng = ctx.rng
    for _ in range(rng.randint(3, 8)):
        ip = f"{EXTERNAL_MISC_NET}.{rng.randint(100, 250)}"
        t = local(ctx.day, rng.uniform(0, 23.9))
        for name in rng.sample(("admin", "test", "oracle", "ubuntu", "pi", "user"), rng.randint(1, 2)):
            pid = ctx.next_pid()
            port = ctx.next_port()
            ctx.out.append(ev.ssh_invalid_user("srv-web01", t, pid, name, ip, port))
            ctx.out.append(ev.ssh_failed("srv-web01", t + timedelta(seconds=2), pid, name, ip, port, invalid=True))
            t += timedelta(seconds=rng.randint(3, 30))


def generate_day(
    org: Organisation, rng: random.Random, day: date, events_per_day: int, holidays: frozenset[date]
) -> list[Record]:
    weekend = day.weekday() >= 5 or day in holidays
    ctx = DayContext(org, rng, day)
    sessions: list[tuple[User, datetime, str, str]] = []
    for user in org.users:
        if weekend:
            if rng.random() < 0.04 and user.remote:
                for when, ip, server in _remote_day(ctx, user, rng.uniform(10, 15)):
                    sessions.append((user, when, ip, server))
            continue
        if rng.random() < 0.05:  # absent (vacation, sick leave)
            continue
        start = user.start_hour + rng.uniform(-0.25, 0.25)
        end = user.end_hour + rng.uniform(-0.25, 0.4)
        if user.remote and rng.random() < 0.6:
            slots = _remote_day(ctx, user, start)
        else:
            slots = _office_day(ctx, user, start, end)
        sessions.extend((user, w, ip, s) for w, ip, s in slots)
    if not weekend:
        for admin in org.admins:
            if rng.random() < 0.95:
                _admin_day(ctx, admin)
    _service_accounts(ctx, weekend)
    _internet_noise(ctx)
    # background network chatter scales the volume to events_per_day
    target = events_per_day if not weekend else max(events_per_day // 10, 1)
    index = 0
    while len(ctx.out) + 2 <= target and sessions:
        user, start_t, ip, server = sessions[index % len(sessions)]
        index += 1
        user_end = start_t + timedelta(hours=user.end_hour - user.start_hour if not weekend else 3)
        span = max((user_end - start_t).total_seconds(), 60)
        when = start_t + timedelta(seconds=rng.uniform(60, span))
        _network_session(ctx, user, when, ip, server)
    return ctx.out


def record_time(rec: Record) -> datetime:
    return rec.time


def is_windows(rec: Record) -> bool:
    return isinstance(rec, WinRecord)


def is_syslog(rec: Record) -> bool:
    return isinstance(rec, SysRecord)

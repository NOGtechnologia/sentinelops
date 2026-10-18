"""The fictitious company "Musterfirma GmbH" (spec section 11).

Only reserved identifiers are used: the domain ``musterfirma.example`` (RFC
2606), internal addresses from RFC 1918 and external addresses exclusively
from the RFC 5737 documentation ranges. Names are generic German first/last
name combinations and do not refer to real persons.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

DOMAIN = "musterfirma.example"
NETBIOS = "MUSTERFIRMA"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"

#: RFC 5737 ranges (external in the test data).
EXTERNAL_HOME_NET = "198.51.100"  # home offices of remote employees
EXTERNAL_ATTACK_NET = "203.0.113"  # attackers
EXTERNAL_MISC_NET = "192.0.2"  # misc. internet noise / unusual logons

FIRST_NAMES = (
    "anna", "ben", "clara", "david", "emma", "felix", "greta", "hannah", "jonas", "julia", "karl", "lara",
    "lena", "lukas", "marie", "max", "mia", "noah", "paul", "petra", "sabine", "sophie", "stefan", "thomas",
    "tim", "ute", "vera", "wolfgang", "yvonne", "zoe", "erika", "frank", "heike", "ingo", "jana", "kai",
)
LAST_NAMES = (
    "becker", "fischer", "hoffmann", "klein", "koch", "krueger", "lange", "meier", "mueller", "neumann",
    "richter", "schaefer", "schmidt", "schneider", "schroeder", "schulz", "wagner", "weber", "wolf", "zimmermann",
    "braun", "hartmann", "lehmann", "werner", "kraus", "vogel", "jung", "roth", "frank", "beck",
)
DEPARTMENTS = (
    ("Vertrieb", 24), ("Einkauf", 10), ("Buchhaltung", 12), ("Personal", 6), ("IT", 8), ("Produktion", 40),
    ("Marketing", 10), ("Logistik", 20), ("Geschaeftsfuehrung", 4), ("Qualitaet", 12),
)


@dataclass(frozen=True)
class User:
    name: str  # sAMAccountName, e.g. erika.muster
    display: str
    department: str
    rid: int
    workstation: str
    start_hour: float  # typical work start (local time)
    end_hour: float
    remote: bool
    home_ip: str | None
    linux: bool = False

    @property
    def sid(self) -> str:
        return f"{DOMAIN_SID}-{self.rid}"


@dataclass(frozen=True)
class Host:
    name: str  # short name, e.g. dc01
    ip: str
    os: str  # windows | linux | appliance
    role: str  # dc | server | workstation | gateway | linux | vpn

    @property
    def fqdn(self) -> str:
        return f"{self.name.upper()}.{DOMAIN}" if self.os == "windows" else self.name


@dataclass
class Organisation:
    users: list[User]
    admins: list[User]  # privileged admin accounts (adm-*)
    service_accounts: list[str]
    workstations: list[Host]
    servers: list[Host]
    linux_servers: list[Host]
    vpn: Host
    privileged_groups: tuple[str, ...] = ("Domain Admins", "Enterprise Admins", "Administrators", "sudo", "wheel")
    normal_groups: tuple[str, ...] = ("GG-Vertrieb-Share", "GG-VPN-Users", "GG-Drucker-EG", "GG-Projekt-Alpha", "docker")
    by_name: dict[str, User] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.by_name = {u.name: u for u in [*self.users, *self.admins]}

    @property
    def dcs(self) -> list[Host]:
        return [h for h in self.servers if h.role == "dc"]

    def server(self, name: str) -> Host:
        return next(h for h in [*self.servers, *self.linux_servers] if h.name == name)

    def host_by_name(self, name: str) -> Host:
        return next(h for h in [*self.workstations, *self.servers, *self.linux_servers, self.vpn] if h.name == name)


def build_organisation(rng: random.Random) -> Organisation:
    workstations = [Host(f"ws-{i:04d}", f"10.20.{i // 200 + 1}.{i % 200 + 10}", "windows", "workstation") for i in range(1, 121)]
    servers = [
        Host("dc01", "10.10.0.10", "windows", "dc"),
        Host("dc02", "10.10.0.11", "windows", "dc"),
        Host("srv-file01", "10.10.0.20", "windows", "server"),
        Host("srv-file02", "10.10.0.21", "windows", "server"),
        Host("srv-app01", "10.10.0.30", "windows", "server"),
        Host("srv-sql01", "10.10.0.31", "windows", "server"),
        Host("srv-mail01", "10.10.0.40", "windows", "server"),
        Host("srv-print01", "10.10.0.50", "windows", "server"),
        Host("srv-backup01", "10.10.0.60", "windows", "server"),
        Host("srv-gw01", "10.10.0.70", "windows", "gateway"),
    ]
    linux_servers = [
        Host("srv-lnx01", "10.30.0.11", "linux", "linux"),
        Host("srv-lnx02", "10.30.0.12", "linux", "linux"),
        Host("srv-lnx03", "10.30.0.13", "linux", "linux"),
        Host("srv-lnx04", "10.30.0.14", "linux", "linux"),
        Host("srv-web01", "10.30.0.20", "linux", "linux"),
    ]
    vpn = Host("vpn01", "10.10.0.80", "appliance", "vpn")

    names: list[tuple[str, str]] = []
    seen: set[str] = set()
    while len(names) < sum(n for _, n in DEPARTMENTS):
        first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
        name = f"{first}.{last}"
        if name in seen:
            continue
        seen.add(name)
        names.append((name, f"{first.capitalize()} {last.capitalize()}"))
    # Fixed personas used by the attack scenarios (stable across seeds so the
    # documentation and screenshots can refer to them).
    personas = [
        ("jonas.becker", "Jonas Becker", "Vertrieb", True),
        ("anna.schmidt", "Anna Schmidt", "Einkauf", True),
        ("petra.wagner", "Petra Wagner", "Buchhaltung", False),
        ("thomas.klein", "Thomas Klein", "Logistik", False),
        ("sabine.koch", "Sabine Koch", "Personal", False),
        ("lena.hoffmann", "Lena Hoffmann", "Marketing", False),
        ("max.mustermann", "Max Mustermann", "IT", False),
        ("erika.muster", "Erika Muster", "Vertrieb", True),
    ]
    persona_names = {p[0] for p in personas}
    names = [n for n in names if n[0] not in persona_names][: len(names) - len(personas)]

    users: list[User] = []
    rid = 1101
    ws_index = 0
    remote_index = 10
    slots: list[tuple[str, str, str, bool | None]] = [(n, d, dep, r) for n, d, dep, r in personas]
    for dept, count in DEPARTMENTS:
        for _ in range(count - sum(1 for p in personas if p[2] == dept)):
            name, display = names.pop(0)
            slots.append((name, display, dept, None))
    for name, display, dept, remote_flag in slots:
        remote = remote_flag if remote_flag is not None else (dept in ("Vertrieb", "Marketing", "Einkauf") and rng.random() < 0.5)
        if dept == "Produktion":
            # production staff share terminals
            workstation = workstations[100 + (rid % 20)].name
        else:
            workstation = workstations[ws_index % 100].name
            ws_index += 1
        start = rng.choice((6.0, 6.5, 7.0, 7.5, 8.0, 8.5, 9.0)) if dept != "Produktion" else rng.choice((5.75, 13.75))
        end = start + rng.choice((8.0, 8.5, 9.0, 9.5))
        home_ip = None
        if remote:
            home_ip = f"{EXTERNAL_HOME_NET}.{remote_index}"
            remote_index += 1
        users.append(User(name, display, dept, rid, workstation, start, end, remote, home_ip, linux=dept == "IT"))
        rid += 1
    admins = [
        User("adm-mueller", "Admin Mueller", "IT", 1500, "ws-0005", 7.0, 16.0, False, None, linux=True),
        User("adm-weber", "Admin Weber", "IT", 1501, "ws-0006", 8.0, 17.0, False, None, linux=True),
        User("adm-schulz", "Admin Schulz", "IT", 1502, "ws-0007", 7.5, 16.5, False, None, linux=True),
        User("adm-richter", "Admin Richter", "IT", 1503, "ws-0008", 9.0, 18.0, False, None, linux=True),
    ]
    return Organisation(
        users=users,
        admins=admins,
        service_accounts=["svc_backup", "svc_monitor", "svc_sql", "svc_deploy"],
        workstations=workstations,
        servers=servers,
        linux_servers=linux_servers,
        vpn=vpn,
    )

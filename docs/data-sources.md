# Datenquellen, Lizenzen und Belege

Stand: 18.10.2026. Jede Fremdquelle im Repository mit Herkunft, Lizenz und Abrufdatum.

## Erkennungsregeln

| Quelle | Inhalt | Lizenz | Herkunft |
|---|---|---|---|
| SigmaHQ/sigma | 3 kuratierte, **unveränderte** Regeln in `rules/sigma/sigmahq/` | Detection Rule License (DRL) 1.1 | Commit `b7920ed31356fb7f6a9275b34737d8604c65bac3`, abgerufen 18.10.2026 – Details in `rules/sigma/sigmahq/SOURCE.md`; Original: <https://github.com/SigmaHQ/sigma> |
| SentinelOps | Eigene Regeln `SO-*` (`rules/sigma/custom/`, `rules/correlations/`, `rules/baselines/`) | Apache-2.0 (wie der Code) | eigene Arbeit |

Die DRL 1.1 verlangt die Nennung der Autorinnen und Autoren bei Nutzung der Regeln. SentinelOps
zeigt `author`, Quelle und Lizenz jeder Regel in der Regel-API/-Ansicht, im generierten
Regelkatalog und im Fallbericht (Abschnitt „Regeln und Herkunft“).

## Test-Fixtures

| Datei | Herkunft | Lizenz |
|---|---|---|
| `backend/tests/fixtures/evtx/security.evtx`, `new-user-security.evtx` | Beispieldateien des Projekts [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (`samples/`) | MIT – [`LICENSE-MIT`](https://github.com/omerbenamram/evtx/blob/master/LICENSE-MIT) liegt neben den Dateien |
| alle übrigen Fixtures (`windows_xml`, `windows_json`, `syslog_*`, `journald`, `json_vpn`) | selbst erstellt nach den unten belegten Formaten, nur RFC-5737-/RFC-1918-Adressen und `musterfirma.example` | Apache-2.0 |
| Golden Files `*.golden.json` | aus den Parsern erzeugt, **manuell gegengeprüft** (siehe Git-Historie) | Apache-2.0 |

Die EVTX-Beispieldateien enthalten Rechner- und Kontonamen aus der Testumgebung der
Bibliotheksautoren. Sie dienen ausschließlich Parser-Tests, werden nicht in Demo-Daten oder
Screenshots verwendet und sind von der Prüfung auf Nicht-RFC-5737-IPs ausgenommen, weil diese
nur Textdateien prüft.

## Testdaten (Generator)

Alle Demo- und Benchmarkdaten erzeugt der Generator `generator/` deterministisch (Seeds `dev`,
`holdout`). Firma, Personen, Hosts und Adressen sind **fiktiv**: Domäne `musterfirma.example`
(RFC 2606 reserviert `.example`), interne Netze aus RFC 1918, externe Angreifer- und
Partneradressen aus RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Formate und Event-IDs (Belege)

| Thema | Beleg |
|---|---|
| Windows-Sicherheitsereignisse 4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4756, 4768, 4771, 4776, 1102 | Microsoft Learn, „Audit …“-Referenz je Event-ID: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624> (analog je ID) |
| Logon-Typen (2, 3, 7, 10, 11 …) | Microsoft Learn, Event 4624, Tabelle „Logon types“ (gleiche Quelle) |
| Fehlercodes 4625 (`Status`/`SubStatus`, z. B. `0xC000006A`) | Microsoft Learn, Event 4625 |
| Windows-Event-XML-Schema | <https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema> |
| Syslog RFC 3164 | <https://datatracker.ietf.org/doc/html/rfc3164> |
| Syslog RFC 5424 | <https://datatracker.ietf.org/doc/html/rfc5424> |
| journald JSON-Export | <https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html> |
| OpenSSH-Logzeilen (`Failed password`, `Accepted publickey`, …) | Quelltext OpenSSH `auth.c` / `auth2.c`, <https://www.openssh.com/> |
| sudo-Logformat | <https://www.sudo.ws/docs/man/sudoers.man/> (Abschnitt „Log format“) |
| ECS-Feldnamen (Teilmenge) | Elastic Common Schema: <https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html> |
| Sigma-Spezifikation (Regeln, Modifikatoren, Korrelationen) | <https://github.com/SigmaHQ/sigma-specification> |
| MITRE ATT&CK-Techniken der Regeln | <https://attack.mitre.org/> |
| Dokumentations-IP-Bereiche | RFC 5737: <https://datatracker.ietf.org/doc/html/rfc5737> |

## Bibliotheken (Laufzeit, Backend)

| Paket | Version | Lizenz | Zweck |
|---|---|---|---|
| fastapi | 0.146.0 | MIT | API |
| pydantic | 2.14.1 | MIT | Validierung |
| sqlalchemy | 2.1.5 | MIT | Datenbankzugriff |
| asyncpg | 0.32.0 | Apache-2.0 | PostgreSQL-Treiber |
| alembic | 1.20.0 | MIT | Migrationen |
| pysigma | 2.0.1 | LGPL-2.1-only | Sigma-Parsing/-Validierung (unverändert, dynamisch genutzt) |
| evtx | 0.13.1 | MIT | EVTX-Parser (Rust, `omerbenamram/evtx`) |
| defusedxml | 0.7.1 | PSF | sicheres XML-Parsing |
| jinja2 | 3.1.6 | BSD-3-Clause | Berichtsvorlagen |
| fpdf2 | 2.8.9 | LGPL-3.0-only | PDF-Berichte (unverändert, dynamisch genutzt) |
| pyjwt[crypto] | 2.15.1 | MIT | OIDC-Token-Prüfung |
| httpx | 0.28.1 | BSD-3-Clause | OIDC/KI-HTTP |
| anthropic | 1.15.0 | MIT | optionaler Cloud-KI-Anbieter |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI-Server |
| pyyaml | 6.0.3 | MIT | Regeln/Konfiguration (`safe_load`) |
| python-multipart | 0.0.32 | Apache-2.0 | Uploads |
| tzdata | 2026.5 | Apache-2.0 | Zeitzonendaten |

LGPL-Bibliotheken werden als eigenständige, austauschbare Python-Pakete genutzt und nicht
verändert. Nach unserem Verständnis ist das mit Apache-2.0 vereinbar (keine Rechtsberatung);
die Hinweise stehen in der Datei `NOTICE` im Wurzelverzeichnis.

## Schriften

| Schrift | Verwendung | Lizenz |
|---|---|---|
| Inter | Oberfläche, PDF | SIL Open Font License 1.1 (`LICENSE-Inter.txt`) |
| JetBrains Mono | Logzeilen, PDF | SIL Open Font License 1.1 (`LICENSE-JetBrainsMono.txt`) |
| DejaVu Sans | PDF-Fallback für Sonderzeichen | Bitstream Vera / DejaVu-Lizenz (`LICENSE-DejaVu.txt`) |

Alle Schriften sind selbst gehostet (`frontend/public/fonts/`, `backend/src/sentinelops/reports/fonts/`).

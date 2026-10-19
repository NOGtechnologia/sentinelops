# Kanonisches Schema

Alle Quellen werden auf dieses Schema normalisiert ([ADR-0002](adr/0002-schema.md)). Feldnamen
folgen dem Elastic Common Schema, soweit vorhanden. Definiert in
`backend/src/sentinelops/normalize/schema.py`.

## Felder

| Feld | Typ | Bedeutung |
|---|---|---|
| `event.id` | string | Deterministische ID: Hash aus Quell-Fingerprint (siehe Duplikate) |
| `@timestamp` | datetime (UTC, µs) | Normalisierter Zeitpunkt |
| `event.original_time` | string | Zeitangabe wie in der Quelle |
| `event.time_quality` | enum | `exact`, `assumed_timezone`, `inferred_year`, `clock_skew_suspected` |
| `event.ingested` | datetime | Zeitpunkt des Imports |
| `event.kind` | string | `event` |
| `event.category` | list | z. B. `authentication`, `iam`, `process` |
| `event.type` | list | z. B. `start`, `end`, `creation`, `change` |
| `event.action` | string | z. B. `logon-failed`, `logon`, `user-created`, `group-member-added`, `log-cleared` |
| `event.outcome` | enum | `success`, `failure`, `unknown` |
| `event.code` | string | Event-ID der Quelle (Windows) |
| `event.provider` | string | Provider/Programm (z. B. `Microsoft-Windows-Security-Auditing`, `sshd`) |
| `user.name` / `user.domain` / `user.id` | string | handelnde Identität |
| `user.target.name` / `.domain` / `.id` | string | Zielkonto (z. B. bei 4720, 4724, 4728) |
| `group.name` / `group.id` | string | betroffene Gruppe |
| `host.name` | string | protokollierendes System |
| `host.os.type` | string | `windows`, `linux` |
| `source.ip` / `source.port` / `source.host` | string/int | Herkunft der Anmeldung |
| `logon.type` | int | Windows-Logon-Typ (2, 3, 7, 10, 11 …) |
| `auth.method` | string | `password`, `publickey`, `kerberos`, `ntlm` |
| `process.name` / `process.pid` / `process.command_line` | string/int | Prozessangaben (z. B. sudo) |
| `log.source_type` | string | Quelltyp (siehe unten) |
| `log.raw_record_id` | string | Verweis auf den unveränderten Rohsatz |
| `message` | string | Klartext der Meldung (Syslog) |
| `quality.flags` | list | weitere Qualitätshinweise |

Quellspezifische Originalfelder bleiben unter `winlog.event_data.*` erhalten (für SigmaHQ-Regeln).

## Quelltypen

`windows_evtx`, `windows_xml`, `windows_json`, `syslog_3164`, `syslog_5424`, `journald_json`
sowie `json:<profil>` für JSON-Quellen mit Mapping-Profil (`ingest/profiles/*.yaml`, z. B.
`json:musterfirma_vpn`, `json:generic`). Linux-Auth-Meldungen (sshd, sudo, useradd, passwd, su)
werden innerhalb der Syslog-/journald-Parser über benannte Muster erkannt.

## Verarbeitungsstatus eines Rohsatzes

| Status | Bedeutung |
|---|---|
| `accepted` | normalisiert, Event gespeichert |
| `duplicate` | gleicher Fingerprint wie ein bereits gespeichertes Event (`duplicate_of`) |
| `malformed` | nicht verarbeitbar – mit Fehlercode, landet in der Quarantäne |

Fehlercodes: `PARSE_ERROR`, `MISSING_TIMESTAMP`, `INVALID_ENCODING`, `SCHEMA_VIOLATION`,
`TRUNCATED`, `OVERSIZED`.

## Duplikate

Fingerprint je Format: Windows aus Kanal, Computer, `EventRecordID` und Zeit; Syslog aus Host,
Zeit, Programm und Nachricht; JSON aus den im Profil benannten Schlüsselfeldern. Ein erneuter
Import derselben Datei (gleicher SHA-256) wird übersprungen; dieselben Datensätze aus einer anderen
Datei werden als `duplicate` erkannt. Zählungen ändern sich dadurch nicht (A3).

## Zeit

- Speicherung immer UTC; Anzeige in `SENTINELOPS_DISPLAY_TZ` (Standard `Europe/Berlin`).
- Quellen ohne Zeitzone: Zeitzone der Quelle/des Imports, Kennzeichen `assumed_timezone`;
  mehrdeutige oder nicht existierende lokale Zeiten bei Zeitumstellung werden markiert.
- RFC 3164 ohne Jahr: Jahr aus Importzeitpunkt abgeleitet (`inferred_year`).
- Zeitversatz einer Quelle über der Toleranz: `clock_skew_suspected`.

## Datenbank

PostgreSQL 16; `events` nach UTC-Tag partitioniert (`events_YYYYMMDD`, `events_default`),
Rohdaten in `raw_records` (Text, zusätzlich Bytes, wenn nicht verlustfrei als UTF-8 darstellbar),
Volltext über `tsvector` ([ADR-0006](adr/0006-volltextsuche.md)), Audit-Log append-only mit
Hash-Kette. Migrationen: `backend/migrations/` (Alembic, `sentinelops migrate`).

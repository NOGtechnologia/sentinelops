# ADR-0002: Kanonisches Schema als ECS-Teilmenge

## Kontext

Windows-Ereignisse (EVTX/XML/JSON), Syslog (RFC 3164/5424), journald und JSON-Quellen müssen
einheitlich ausgewertet werden. Sigma-Regeln aus SigmaHQ verwenden Windows-Feldnamen
(`EventID`, `TargetUserName`, …).

## Entscheidung

- Ein kleines kanonisches Schema mit **Feldnamen des Elastic Common Schema** (`@timestamp`,
  `event.code`, `event.action`, `event.outcome`, `user.name`, `user.target.name`, `host.name`,
  `source.ip`, `process.command_line`, `group.name`, …) plus Herkunfts- und Qualitätsfeldern
  (`raw_record_id`, `time_quality`, `quality.flags`). Vollständige Liste: [Schema](../schema.md).
- Quellspezifische Originalfelder bleiben unter `winlog.event_data.*` erhalten, damit
  SigmaHQ-Regeln über die Processing-Pipeline (`rules/pipelines/sentinelops.yml`) auswertbar sind.
- Events sind unveränderliche Werte; Rohdaten werden nie verändert (Regel 6).
- Zeit immer UTC mit Mikrosekunden, Qualitätskennzeichen bei angenommener Zeitzone,
  abgeleitetem Jahr oder Zeitversatz.

## Alternativen

- Volles ECS: zu groß, viele Felder ohne Quelle in V1.
- OCSF: weniger verbreitet in Sigma-Pipelines, keine fertigen Mappings für die V1-Quellen.
- Rohfelder je Quelle: Regeln müssten je Quelle dupliziert werden.

## Konsequenzen

Neue Quellen brauchen ein Mapping (Parser oder `json_mapped`-Profil) mit Beispielen, die beim
Laden validiert werden. Feldänderungen sind Schema-Versionen und brauchen eine Migration.

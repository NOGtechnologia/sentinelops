# SentinelOps

**Erklärbares, KI-gestütztes Security-Operations-Werkzeug: von 50.000 Log-Zeilen zum untersuchbaren Fall.**

SentinelOps importiert Windows-Ereignisprotokolle, Linux-Syslogs und strukturierte JSON-Ereignisse,
erkennt Angriffe mit Sigma- und Korrelationsregeln, bündelt zusammengehörige Alarme zu **einem** Fall
und erklärt jede Priorität mit Belegen. Eine optionale KI fasst den Fall zusammen – technisch
gezwungen, nur Belegtes zu behaupten. Maßnahmen schlägt das System vor; ein Mensch gibt sie frei.

![Falldetail mit Priorität, Begründung und Zusammenfassung](images/case-overview-dark.png)

## Grundprinzipien

| Prinzip | Umsetzung |
|---|---|
| Regeln vor KI | Deterministische Erkennung mit Sigma-, Korrelations- und Baseline-Regeln; die KI sieht erst den fertigen Fall. |
| Jede Aussage hat Belege | Prioritätsfaktoren, Fakten und Hypothesen verweisen auf nummerierte Belege E1…En mit Rohzeile. |
| Nachvollziehbarkeit | Regel-YAML mit hervorgehobener Bedingung, passende Felder und Rohzeilen zu jedem Alarm. |
| Mensch entscheidet | Maßnahmen nur als Vorschlag; Freigabe durch L2 mit Begründung, Vier-Augen-Prinzip, signiert. |
| Reproduzierbarkeit | Gleiche Daten und Regeln ⇒ identische Fälle und byte-identische Berichte. |
| Läuft ohne echte Daten | Generator „Musterfirma GmbH“ mit Angriffsszenarien und Ground Truth. |

## Einstieg

- [Rundgang](tour.md) – ein Angriff vom Log bis zur freigegebenen Maßnahme, mit allen Ansichten
- [Benutzerhandbuch](user-guide/index.md) – Arbeiten mit Lagebild, Fällen, Belegen und Maßnahmen
- [Installation und Betrieb](operations.md) – Demo in fünf Befehlen, Konfiguration, Aufbewahrung
- [Erkennungskatalog](detection-catalog.md) – alle Regeln mit Logik, Schwellen und Tests
- [KI-Prinzipien](ai.md) – Evidenz-Paket, Validator, Anbieter, Datenschutz
- [Datenschutz](privacy.md) und [Bedrohungsmodell](threat-model.md)

!!! warning "Haftungsausschluss"
    SentinelOps ergänzt bestehende SIEM- und EDR-Produkte und ersetzt sie nicht. Alle Demo-Daten sind
    fiktiv. Die Hinweise zu Datenschutz und Mitbestimmung sind keine Rechtsberatung.

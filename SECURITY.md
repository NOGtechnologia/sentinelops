# Sicherheitsrichtlinie / Security policy

## Unterstützte Versionen

| Version | Sicherheitsupdates |
|---|---|
| 1.x (aktuell) | ✅ |
| < 1.0 | ❌ |

## Schwachstelle melden

Bitte melden Sie Sicherheitslücken **vertraulich** über die GitHub-Funktion
„Report a vulnerability“ (Private Vulnerability Reporting) dieses Repositorys –
**nicht** als öffentliches Issue.

Bitte angeben:

- betroffene Version bzw. Commit,
- Beschreibung und Auswirkung,
- Schritte zur Reproduktion mit **synthetischen** Daten (keine echten Logs oder Zugangsdaten),
- ggf. Vorschlag zur Behebung.

Wir bestätigen den Eingang in der Regel innerhalb von 5 Werktagen, bewerten die Meldung und
stimmen einen Veröffentlichungszeitpunkt ab (Coordinated Disclosure, üblicherweise ≤ 90 Tage).
Meldende werden auf Wunsch im Changelog genannt.

## Umfang

Im Fokus stehen insbesondere: Umgehung von Authentifizierung oder Rollenrechten, Ausführung von
Maßnahmen ohne gültige Freigabe, XSS/Injection über Logdaten, Prompt-Injection mit Wirkung auf
Maßnahmen oder unbelegte Aussagen, Manipulation des Audit-Logs, Offenlegung personenbezogener Daten.

Nicht im Umfang: Befunde, die nur im Demo-Modus mit bekannten Demo-Zugängen bestehen (der
Demo-Modus ist nicht für den Produktivbetrieb gedacht), sowie Denial-of-Service durch Volumen.

## Härtung im Betrieb

Siehe [docs/operations.md](docs/operations.md), [Bedrohungsmodell](docs/threat-model.md) und
[ASVS-Checkliste](docs/security/asvs.md).

---

**English:** Please report vulnerabilities privately via GitHub's "Report a vulnerability"
(private vulnerability reporting), never as a public issue. Include version, impact and
reproduction steps using synthetic data only. We acknowledge within 5 working days.

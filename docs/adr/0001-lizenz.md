# ADR-0001: Lizenz

## Kontext

Die Spezifikation legt Apache-2.0 für den Code fest (17.5). Kuratierte Regeln aus SigmaHQ stehen
unter der Detection Rule License (DRL) 1.1, die Namensnennung verlangt. Abhängigkeiten stehen unter
MIT, BSD, Apache-2.0, PSF sowie LGPL (pySigma 2.1-only, fpdf2 3.0-only).

## Entscheidung

- Code, eigene Regeln (`SO-*`), Generator, Doku: **Apache-2.0** (`LICENSE`, `NOTICE`).
- SigmaHQ-Regeln bleiben **unverändert** unter DRL 1.1 in `rules/sigma/sigmahq/` mit eigener
  `LICENSE` und `SOURCE.md` (Commit, Abrufdatum, Autor je Regel). SentinelOps-Metadaten stehen
  getrennt in `curation.yaml`. Autor, Quelle und Lizenz erscheinen in Regelansicht, Katalog und
  Fallbericht.
- LGPL-Bibliotheken werden unverändert als eigenständige Pakete genutzt und in `NOTICE` genannt.
- Lizenzprüfung in CI: Allowlist für Abhängigkeiten (`MIT`, `BSD-*`, `Apache-2.0`, `ISC`, `PSF`,
  `MPL-2.0`, `LGPL-*` als Bibliothek, `OFL-1.1` für Schriften), Regel-Lizenzen gesondert.

## Alternativen

- AGPL/GPL: widerspricht der Spezifikation.
- SigmaHQ-Regeln anpassen: verletzt die Trennung von Herkunft und eigener Arbeit; Anpassungen
  erfolgen stattdessen über Pipeline/Ausnahmen.

## Konsequenzen

Änderungen an Lizenzen sind nicht umkehrbar und nur nach Rückfrage zulässig (CLAUDE.md Regel 13).
Keine Rechtsberatung – Bewertung der LGPL-Kompatibilität nach üblichem Verständnis.

# Benutzerhandbuch

Dieses Handbuch richtet sich an Analystinnen und Analysten im Security-Operations-Team. Es beschreibt
den typischen Ablauf vom Lagebild bis zum Bericht. Alle Abbildungen stammen aus dem Demo-Modus mit
den fiktiven Daten der Musterfirma GmbH.

## Anmelden

Im Produktivbetrieb melden Sie sich über den Identitätsanbieter Ihres Unternehmens an (OIDC). Im
**Demo-Modus** bietet die Anmeldeseite Demo-Zugänge für jede Rolle an; sie sind ausschließlich im
Demo-Modus aktiv.

| Rolle | Darf |
|---|---|
| Analyst (L1) | Fälle sichten, bearbeiten, kommentieren, Maßnahmen vorschlagen, Fehlalarme melden, Berichte exportieren |
| Senior Analyst (L2) | zusätzlich Maßnahmen freigeben/ablehnen, Fälle zusammenführen/trennen, Ausnahmen genehmigen |
| Detection Engineer | Regeln aktivieren/deaktivieren, Ausnahmen vorschlagen, Quarantäne neu verarbeiten |
| Administrator | Ingest-Tokens, Datenquellen, Benutzerübersicht, Einstellungen |
| Auditor | alles lesen inkl. Audit-Log |

Die vollständige Matrix steht unter [Rollen und Berechtigungen](../permissions.md).

## Bedienung

- **Sprache** (DE/EN) und **Design** (dunkel/hell) oben rechts.
- **Suche** (`/`) durchsucht Fall-Titel und Fall-IDs.
- **Tastaturkürzel** – Übersicht mit `?`:

| Taste | Wirkung |
|---|---|
| `j` / `k` | nächster / vorheriger Fall in der Warteschlange |
| `Enter` | markierten Fall öffnen |
| `x` | Fall für Massenaktionen auswählen |
| `a` | Fall (bzw. Auswahl) mir zuweisen |
| `1` – `5` | im Fall: Übersicht, Timeline, Belege, Entitätsgraph, Bericht |
| `g` | zum Lagebild |

- **Zeiten** werden in der Anzeigezeitzone dargestellt (Standard Europe/Berlin); der Tooltip zeigt
  den UTC-Wert. Jede Kennzahl nennt Zeitraum und Datenstand.
- **Prioritäten** sind immer an Farbe **und** Symbol **und** Text erkennbar: P1 Achteck (kritisch),
  P2 Dreieck (hoch), P3 Kreis (mittel), P4 Punkt (niedrig).

## Kapitel

1. [Lagebild und Fälle](cases.md)
2. [Belege und Fehlalarme](evidence.md)
3. [Maßnahmen und Freigaben](actions.md)
4. [Berichte](reports.md)
5. [Regeln, Datenqualität, Administration](operations.md)

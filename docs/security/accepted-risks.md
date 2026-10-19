# Akzeptierte Risiken

Jede Ausnahme in einer automatischen Prüfung steht hier mit Begründung, Bewertung und
Wiedervorlage. Ausnahmen ohne Eintrag sind nicht zulässig (CLAUDE.md Regel 4).

## PYSEC-2026-2447 – `diskcache` 5.6.3 (transitiv über pySigma)

- **Prüfung:** `pip-audit` (`make security`, `scripts/tasks.py: PIP_AUDIT_IGNORED`).
- **Befund:** `diskcache` deserialisiert Cache-Einträge mit `pickle`. Wer Schreibzugriff auf das
  Cache-Verzeichnis hat, kann beim Lesen Code ausführen lassen. Es gibt keine korrigierte Version.
- **Nutzung in SentinelOps:** pySigma 2.0.1 importiert `diskcache` für einen optionalen Cache
  externer Daten (z. B. MITRE-Daten). SentinelOps ruft diese Funktionen nicht auf; die
  Container laufen mit schreibgeschütztem Root-Dateisystem als Nicht-root-Benutzer, ein Angreifer
  bräuchte bereits Schreibrechte im Container.
- **Bewertung:** niedrig. **Wiedervorlage:** bei jedem pySigma-Update bzw. sobald ein Fix
  erscheint; Dependabot meldet neue Versionen.

## Bandit-/Ruff-Ausnahmen

Einzelne `# noqa`-Kommentare im Code tragen ihre Begründung direkt an der Stelle (z. B. `S701`
für Jinja2 mit `finalize=md_escape` bei Markdown-Ausgabe, `S314` für das selbst erzeugte
`coverage.xml`). Globale Ausnahmen stehen begründet in `backend/pyproject.toml`.

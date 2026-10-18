"""Generates ``docs/detection-catalog.md`` from the rule set (spec 15.3)."""

from __future__ import annotations

from sentinelops.detection.sigma_loader import RuleSet

HEADER = """# Erkennungskatalog

> Diese Datei wird aus `rules/` **generiert** (`sentinelops rules catalog`); die CI prüft ihre Aktualität.
> Nicht von Hand bearbeiten.

Semantik der Auswertung (eigener Matcher, ADR-0003): Zeichenkettenvergleiche ohne `cased` sind
unabhängig von Groß-/Kleinschreibung, `*`/`?` sind Platzhalter, Keyword-Erkennungen durchsuchen
das Feld `message`. Korrelationen werden in *Bursts* ausgewertet: Treffer einer Gruppe, zwischen
denen höchstens das Zeitfenster liegt, bilden einen Burst; erfüllt irgendein gleitendes Fenster
im Burst die Bedingung, entsteht **ein** Alarm mit **allen** Ereignissen des Bursts.
Erweiterung `sequence` (SO-AUTH-003): Sigma-`temporal_ordered` kann „SO-AUTH-001 **oder**
SO-AUTH-002, danach Erfolg“ nicht ausdrücken; die Erweiterung ist im gleichen YAML-Stil
dokumentiert und getestet.

"""


def render_catalog(ruleset: RuleSet) -> str:
    lines = [
        HEADER,
        "| Regel-ID | Version | Titel | Art | Schweregrad | Reifegrad | ATT&CK | Playbook | Quelle |",
        "|---|---:|---|---|---|---|---|---|---|",
    ]
    thresholds = {c.meta.rule_id: c for c in ruleset.correlations}
    for rule_id in sorted(ruleset.metas):
        m = ruleset.metas[rule_id]
        attack = ", ".join([*m.tactics, *m.techniques])
        lines.append(
            f"| `{m.rule_id}` | {m.version} | {m.title_de} | {m.kind} | {m.level} | {m.maturity} | {attack} | "
            f"{', '.join(m.playbooks)} | {m.source} (`{m.file}`) |"
        )
    lines.append("")
    for rule_id in sorted(ruleset.metas):
        m = ruleset.metas[rule_id]
        lines += [
            f"## {m.rule_id} – {m.title_de}",
            "",
            m.description_de,
            "",
            f"*{m.title}* – {m.description}".strip(),
            "",
        ]
        corr = thresholds.get(rule_id)
        if corr is not None:
            condition = f"{corr.op} {corr.count}" + (f" verschiedene `{corr.value_field}`" if corr.value_field else "")
            group = ", ".join(f"`{g}`" for g in corr.group_by) or "–"
            lines += [
                f"- Korrelation: `{corr.type}` über {', '.join(f'`{r}`' for r in corr.rules)}; "
                f"Gruppierung {group}; Bedingung {condition}; Zeitfenster {corr.timespan_seconds} s",
                "",
            ]
        if m.falsepositives:
            lines += ["- Bekannte Fehlalarmquellen: " + "; ".join(m.falsepositives), ""]
        if m.source == "sigmahq":
            lines += [f"- Autor: {m.author} – Lizenz: Detection Rule License 1.1 (SigmaHQ)", ""]
    return "\n".join(lines).rstrip() + "\n"

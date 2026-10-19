# ADR-0006: Volltextsuche über Rohzeilen

## Kontext

Analysten suchen in Rohzeilen (Spezifikation 12 nennt `pg_trgm`). Bei der Massen-Ingestion
(Ziel ≥ 3.000 Events/s) bestimmt die Pflege der Indizes den Durchsatz.

## Messung

Import des Demo-Datensatzes (≈ 166.000 Events) in Phase 1:

| Index auf `raw_records.content_text` | Ingestion |
|---|---|
| GIN `gin_trgm_ops` | 87 s für den Indexaufbau, Durchsatz deutlich unter Ziel |
| GIN `to_tsvector('simple', left(content_text, 4000))` | ≈ 2,4× günstiger, Gesamtdurchsatz ≈ 3.250 Events/s |

## Entscheidung

- Rohzeilen: **`tsvector`-Wortsuche** (`simple`-Konfiguration, ohne Stemming, erste 4.000 Zeichen).
- `pg_trgm` bleibt für **Ähnlichkeitssuche auf Entitätsnamen** (`ix_entities_key_trgm`).

## Konsequenzen

Teilwortsuche in Rohzeilen (z. B. „admi“) findet nichts; Entitäten (Benutzer, Hosts) sind über
Trigramme unscharf suchbar. Abweichung von 12 ist hiermit begründet.

# ADR-0003: Sigma-Auswertung

## Kontext

Erkennung soll auf Sigma beruhen (6.1). pySigma bietet Parsing, Validierung, Processing-Pipelines
und Korrelationsregeln, aber keinen Auswerter für Events – Backends übersetzen in Abfragesprachen
fremder Systeme. SentinelOps braucht dagegen eine deterministische Auswertung auf eigenen Events
**mit Erklärung**, welche Bedingung mit welchem Feldwert getroffen hat.

## Entscheidung

1. **pySigma 2.0.1** lädt und validiert alle Regeln und wendet die Pipeline an
   (Feld-Mapping `EventID → event.code`, Präfix `winlog.event_data.`, Platzhalter aus der
   Erkennungskonfiguration).
2. Ein **eigener Matcher** (`detection/matcher.py`) übersetzt die geparsten Detection-Objekte in
   Prädikatbäume und wertet sie je Event aus; jede positive Auswertung liefert die passenden
   Detection-Items mit Feldwerten. Nicht unterstützte Features führen beim Laden zu einem Fehler –
   nie zu stillem Ignorieren.
3. **Korrelationen** (`event_count`, `value_count`, `temporal_ordered`) wertet
   `detection/correlation.py` aus; nur die Bedingungen `gte`, `gt`, `eq` sind zugelassen. Alarme
   werden als zusammenhängende „Bursts“ gebildet, damit ein Angriff genau einen Alarm erzeugt.
4. **Erweiterung `sequence`** (`sentinelops_extension: sequence`): „Regel A **oder** B, danach C,
   gleiche Gruppierung, optional gleiche Felder (`same`)“. Standard-`temporal_ordered` verlangt alle
   Regeln und kann das nicht ausdrücken. Erweiterungsregeln sind als solche gekennzeichnet, werden
   vom eigenen Loader gegen die referenzierten Regeln validiert und wie jede Regel getestet.
5. **Baseline-Detektoren** (SO-AUTH-005) sind eigener Code mit Regel-Metadaten in YAML.
6. Prüfung: `sentinelops rules check` (pySigma 2.x + Metadatenschema) **und** die offizielle
   `sigma check` (sigma-cli 3.1.0, isoliert, pySigma 1.5.1) für alle Standardregeln.

## Alternativen

- Übersetzung in SQL über ein pySigma-Backend: keine Treffererklärung auf Feldebene,
  Korrelationen schwer abbildbar, Abhängigkeit von Backend-Semantik.
- Fremde Engines (z. B. Chainsaw, Zircolite): andere Laufzeitumgebungen, keine Integration in
  Fallbildung und Erklärung.

## Konsequenzen

Matcher und Korrelation haben 100 % Zeilen- und Branch-Coverage (15.2); die Semantik ist im
[Erkennungskatalog](../detection-catalog.md) dokumentiert. Neue Sigma-Features müssen bewusst
implementiert werden.

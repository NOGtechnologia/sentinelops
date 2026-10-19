# Architekturentscheidungen (ADR)

Format: Kontext – Entscheidung – Alternativen – Konsequenzen. Status `angenommen`, sofern nicht
anders vermerkt. Der Code verweist mit `ADR-000n` auf diese Dokumente.

| Nr. | Titel | Status |
|---|---|---|
| [0001](0001-lizenz.md) | Lizenz: Apache-2.0 für Code, DRL 1.1 für SigmaHQ-Regeln | angenommen |
| [0002](0002-schema.md) | Kanonisches Schema als ECS-Teilmenge | angenommen |
| [0003](0003-sigma-auswertung.md) | Sigma-Auswertung: pySigma + eigener Matcher, Erweiterung `sequence` | angenommen |
| [0004](0004-queue.md) | Job-Queue in PostgreSQL ohne zusätzlichen Broker | angenommen |
| [0005](0005-evtx.md) | EVTX: Bibliothek `evtx` (Rust); Generator erzeugt XML/JSON | angenommen |
| [0006](0006-volltextsuche.md) | Volltextsuche über `tsvector` statt `pg_trgm` | angenommen |
| [0007](0007-ki-anbieter.md) | KI-Anbieter-Schnittstelle und Absicherung | angenommen |
| [0008](0008-pdf.md) | PDF-Berichte mit fpdf2 statt WeasyPrint | angenommen |

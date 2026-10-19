# Datenschutz und Mitbestimmung

> **Keine Rechtsberatung.** Diese Seite fasst Hinweise für Betreiber zusammen und nennt die
> Quellen, auf denen sie beruhen. Rechtsstand der Recherche: **18.10.2026**. Vor dem Einsatz
> mit echten Daten müssen Betreiber die Rechtslage mit ihrer Datenschutzbeauftragten bzw. ihrem
> Datenschutzbeauftragten und ggf. rechtlicher Beratung prüfen.

## Welche personenbezogenen Daten verarbeitet SentinelOps?

Sicherheitsprotokolle enthalten fast immer personenbezogene Daten von Beschäftigten:

| Datenart | Beispiele in SentinelOps | Wo gespeichert |
|---|---|---|
| Kennungen | Benutzernamen, Konten, SIDs | `events`, `entities`, Rohdaten |
| Netzwerkdaten | Quell-IP-Adressen, Hostnamen | `events`, `entities`, Rohdaten |
| Zeitdaten | Anmeldezeiten → Rückschlüsse auf Arbeitszeiten | `events`, Baselines |
| Verhaltensprofile | Baseline „übliche Netze/Hosts/Uhrzeiten“ je Benutzer (SO-AUTH-005) | Analysezustand |
| Bearbeitungsdaten | Analystinnen und Analysten, Kommentare, Freigaben | `cases`, `audit_log` |

## Hinweise zu Pflichten des Betreibers (DSGVO)

- **Rechtsgrundlage (Art. 6 DSGVO).** Für die Auswertung von Sicherheitsprotokollen kommt
  insbesondere das berechtigte Interesse an der Netz- und Informationssicherheit in Betracht
  (Art. 6 Abs. 1 lit. f DSGVO; Erwägungsgrund 49 nennt die Gewährleistung der Netz- und
  Informationssicherheit ausdrücklich). Quelle: <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
- **Beschäftigtendaten (Art. 88 DSGVO, § 26 BDSG).** Der EuGH hat am 30.03.2023 (C-34/21)
  entschieden, dass nationale Regelungen nur dann „spezifischere Vorschriften“ im Sinne von
  Art. 88 DSGVO sind, wenn sie besondere Schutzmaßnahmen nach Art. 88 Abs. 2 DSGVO enthalten. Die
  Entscheidung betraf die hessische Parallelnorm zu § 26 BDSG. Nach Sekundärquellen hat das BAG
  (8 AZR 209/21, 08.05.2025) § 26 Abs. 1 S. 1 BDSG deshalb unangewendet gelassen; maßgeblich
  sind dann Art. 6 Abs. 1 DSGVO (insb. lit. b, f). `TODO(verify)`: Urteilstext prüfen.
  Quellen: <https://www.dr-datenschutz.de/eugh-kritik-am-deutschen-beschaeftigtendatenschutz/>,
  <https://haufe.de/id/beitrag/datenschutz-41-allgemeines-HI9903024.html>
- **Ein eigenes Beschäftigtendatengesetz** lag als Referentenentwurf (BMAS/BMI, 08.10.2024) vor;
  nach Sekundärquellen war es im Mai 2026 nicht verabschiedet. `TODO(verify)`.
- **Grundsätze (Art. 5 DSGVO):** Zweckbindung (Sicherheit, keine Leistungsbewertung),
  Datenminimierung, Speicherbegrenzung.
- **Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO)** um die Verarbeitung ergänzen.
- **Datenschutz-Folgenabschätzung (Art. 35 DSGVO)** prüfen – systematische Überwachung von
  Beschäftigten kann ein hohes Risiko begründen.
- **Informationspflichten (Art. 13/14 DSGVO)** gegenüber Beschäftigten.

## Mitbestimmung des Betriebsrats

Nach § 87 Abs. 1 Nr. 6 BetrVG hat der Betriebsrat mitzubestimmen bei der Einführung und Anwendung
technischer Einrichtungen, die dazu **bestimmt** sind, das Verhalten oder die Leistung der
Arbeitnehmer zu überwachen. Das BAG lässt in ständiger Rechtsprechung die **objektive Eignung** zur
Überwachung genügen – unabhängig davon, ob der Arbeitgeber eine Überwachung beabsichtigt (Grundsatz
seit BAG 1 ABR 20/74, 09.09.1975; zuletzt bestätigt in der Entscheidung zu Headset-Systemen,
2024). Ein Werkzeug wie SentinelOps, das Anmeldeverhalten einzelner Beschäftigter auswertet, ist
nach dieser Linie **typischerweise mitbestimmungspflichtig**; eine Betriebsvereinbarung ist üblich.

Quellen: <https://www.gesetze-im-internet.de/betrvg/__87.html>,
<https://www.haufe.de/id/entscheidungen/bag-beschluss-vom-09091975-1-abr-2074-HI436774.html>,
<https://www.gleisslutz.com/de/know-how/bag-einfuehrung-eines-headset-systems-ist-mitbestimmungspflichtig>

## Was SentinelOps technisch unterstützt

| Anforderung | Umsetzung |
|---|---|
| Aufbewahrungsfristen je Datenart | Tagespartitionen der Events (`drop_event_partitions_before`), konfigurierbare Fristen für Rohdaten, Fälle und Audit-Log – siehe [Betrieb](operations.md#aufbewahrung) |
| Pseudonymisierung | Optional in Berichten und **immer** vor Cloud-KI-Anbietern (`ai/pseudonymize.py`, stabile Pseudonyme je Fall) |
| Minimalrechte | Rollen `analyst`, `senior_analyst`, `detection_engineer`, `admin`, `auditor` mit Rechten je Route (`permissions.yaml`) |
| Exportprotokollierung | Jeder Bericht-/CSV-Export erzeugt einen Audit-Eintrag |
| Zweckbindung | Keine Ranglisten „aktivste Benutzer“, keine Leistungsauswertung; Entitäten erscheinen nur im Kontext von Alarmen |
| Keine Telemetrie | Keine ausgehenden Verbindungen außer zu konfiguriertem OIDC- und (optional) KI-Anbieter; Schriften und Icons selbst gehostet |
| Lokale KI | Ollama-kompatibler Anbieter – Daten verlassen die eigene Infrastruktur nicht |

## Demo-Daten

Alle mitgelieferten Daten sind **fiktiv** (Musterfirma GmbH, `musterfirma.example`,
IP-Adressen ausschließlich aus RFC 1918 und RFC 5737). Die EVTX-Testdateien stammen aus dem
Open-Source-Projekt `omerbenamram/evtx` und enthalten Testsysteme der Bibliotheksautoren
(siehe [Datenquellen](data-sources.md)).

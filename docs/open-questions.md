# Offene Fragen und Verifikationsbedarf

Punkte, die nicht abschließend belegt werden konnten (`TODO(verify)`), sowie bewusste
Entscheidungen, die eine Rückmeldung der Projektverantwortlichen brauchen.

## Namensprüfung „SentinelOps“ (Phase 0, Spezifikation 17.5)

Stand der Recherche: 2026-10-18 (Websuche, keine Markenrecherche in Registern).

- „Sentinel“ ist im Security-Markt stark belegt, u. a. **Microsoft Sentinel** (SIEM) und
  **SentinelOne** (EDR). SentinelOne bittet in seinen veröffentlichten Markenrichtlinien
  ausdrücklich darum, keine Produkt- oder Firmennamen zu bilden, die ihre Marken mit anderen
  Wörtern kombinieren.
  Quelle: <https://www.sentinelone.com/legal/tm-guidelines/revisions/14/>
- Es existieren weitere Marken mit „Sentinel“ für Sicherheits- bzw. Überwachungssoftware
  (z. B. „SENTINEL SOFTWARE“, Sentinel Software, Inc.).
  Quelle: <https://trademark.justia.com/owners/sentinel-software-inc-1949286>
- Ein eingetragenes Zeichen „SentinelOps“ wurde in der Websuche **nicht** gefunden.

**Bewertung (keine Rechtsberatung):** Ein Verwechslungsrisiko ist plausibel, weil Klasse
(Software) und Branche (Security) identisch sind. **Empfehlung:** Vor einer Veröffentlichung
unter diesem Namen eine Registerrecherche (DPMA, EUIPO, USPTO) durchführen oder einen
neutralen Namen wählen. Der Produktname ist zentral konfigurierbar
(`backend/src/sentinelops/settings.py: PRODUCT_NAME`, Frontend `src/config.ts` + i18n),
der Paketname `sentinelops` ist nur technisch.

**Status:** offen – Entscheidung der Projektverantwortlichen vor dem Veröffentlichen
(wird vor `publish_github.sh` erfragt).

## Rechtliches (siehe `docs/privacy.md`)

- `TODO(verify)`: Anwendbarkeit von § 26 Abs. 1 BDSG nach EuGH C-34/21 und BAG 8 AZR 209/21
  (08.05.2025) – Darstellung beruht auf Sekundärquellen; Urteilstext prüfen.
- `TODO(verify)`: Stand des Beschäftigtendatengesetzes (Referentenentwurf vom 08.10.2024) –
  laut Sekundärquellen im Mai 2026 nicht verabschiedet.

## Technik

- `sigma-cli` 3.1.0 (aktuell, Stand 2026-10-18) bringt pySigma **1.5.1** mit, das Produkt nutzt
  pySigma **2.0.1**. `make rules-check` führt deshalb `sigma check --fail-on-error --fail-on-issues`
  in einer isolierten Umgebung (`uvx`) über alle Standardregeln aus **und** validiert mit pySigma 2.x
  im eigenen Loader. Die Regel SO-AUTH-003 nutzt die dokumentierte Erweiterung `sequence`
  ([ADR-0003](adr/0003-sigma-auswertung.md)) und wird nur vom eigenen Loader geprüft.
- `diskcache` (transitive Abhängigkeit von pySigma) hat eine bekannte Schwachstelle ohne
  Fix-Release (PYSEC-2026-2447) – akzeptiert und begründet in
  [`security/accepted-risks.md`](security/accepted-risks.md).
- Lokale Entwicklungsumgebung ohne Docker: Compose-Stack, Testcontainers-Keycloak, ZAP,
  Trivy und Lighthouse laufen ausschließlich in der CI (`.github/workflows/`).

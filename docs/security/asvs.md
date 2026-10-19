# OWASP ASVS – Abdeckung (Orientierung Level 2)

Referenz: OWASP Application Security Verification Standard 4.0.3
(<https://owasp.org/www-project-application-security-verification-standard/>). Die Tabelle
fasst die für SentinelOps relevanten Kapitel zusammen; „Nachweis“ nennt Test oder Konfiguration.
Status: ✅ umgesetzt · ➖ nicht anwendbar · ⚠ teilweise / Betreiberaufgabe.

| Kapitel | Anforderung (verkürzt) | Status | Umsetzung / Nachweis |
|---|---|:-:|---|
| V1 Architektur | Bedrohungsmodell, Vertrauensgrenzen | ✅ | [Bedrohungsmodell](../threat-model.md) |
| V1.4 | Zentrale Zugriffskontrolle | ✅ | `permissions.yaml` + `require()`-Abhängigkeit für jede Route; App startet nicht bei Lücken |
| V2 Authentifizierung | Delegiert an OIDC-IdP (Passwortregeln, MFA) | ⚠ | Keycloak-Realm; MFA-Richtlinie ist Betreiberaufgabe |
| V2.10 | Dienst-Anmeldedaten nicht im Code | ✅ | Ingest-Tokens zufällig, nur Hash gespeichert; gitleaks |
| V3 Sitzungen | Token statt Cookie-Sitzung, kurze Laufzeit | ✅ | OIDC-Access-Token (Laufzeit im IdP), Token nur im Speicher des Browsers |
| V3.5 | Token-Prüfung: Signatur, `iss`, `aud`, `exp` | ✅ | `test_auth.py::test_oidc_token_verified_with_jwks_and_cached` |
| V4 Zugriffskontrolle | Least Privilege, serverseitig | ✅ | Rollenmatrix ([Berechtigungen](../permissions.md)), `test_every_route_enforces_authentication_and_permissions` |
| V4.2 | Schutz vor IDOR | ✅ | Kein Mandantenmodell; alle Objekte gleichen Rechten unterworfen |
| V4.3 | Administrative Funktionen getrennt | ✅ | `admin:manage`, Audit |
| V5 Validierung/Kodierung | Eingaben validiert (Pydantic, Limits) | ✅ | Pydantic-Modelle, Größen-/Tiefenlimits beim Parsen |
| V5.2 | Ausgabe-Kodierung (XSS) | ✅ | React-Textknoten, kein `dangerouslySetInnerHTML` (Semgrep), Playwright-XSS-Suite |
| V5.3 | SQL-Injection | ✅ | SQLAlchemy-Parameter, Ruff `S608`, Semgrep-Regel |
| V5.3.x | CSV-/Formel-Injection | ✅ | `reports/csv_export.py`, Tests |
| V5.5 | Sichere Deserialisierung | ✅ | `yaml.safe_load`, kein `pickle`, `defusedxml` |
| V7 Fehler/Logging | Keine Stacktraces nach außen; Audit sicherheitsrelevanter Ereignisse | ✅ | Fehlerantworten `{"detail"}`; Audit-Log mit Hash-Kette |
| V7.3 | Log-Injection | ✅ | Logdaten werden nie interpretiert; Anzeige escaped |
| V8 Datenschutz | Sensible Daten minimieren, Aufbewahrung | ✅ | Aufbewahrung je Datenart, Pseudonymisierung, [Datenschutz](../privacy.md) |
| V9 Kommunikation | TLS | ⚠ | TLS über Reverse-Proxy (Betreiber); HSTS gesetzt |
| V10 Schadcode | Abhängigkeiten geprüft, keine dynamische Codeausführung | ✅ | pip-audit, pnpm audit, Dependabot, Semgrep `no-eval` |
| V11 Geschäftslogik | Missbrauchsschutz, Reihenfolge | ✅ | Zustandsautomat Maßnahmen, Vier-Augen, signierte Freigaben (A7) |
| V12 Dateien | Upload-Limits, kein Ausführen, kein Pfadzugriff | ✅ | Spool in Temp-Datei, 512 MiB Limit, Dateiname nur als Metadatum |
| V13 API | Schema, Content-Type, Rate-Limits | ✅ | OpenAPI, `oasdiff`, `RateLimitMiddleware` |
| V13.2 | CSRF für zustandsändernde Anfragen | ✅ | Bearer-Token + Origin-Prüfung (`test_cross_origin_writes_rejected`) |
| V14 Konfiguration | Header (CSP, HSTS, nosniff, Referrer), keine Debug-Ausgabe | ✅ | `api/security.py`, ZAP-Baseline in E2E |
| V14.2 | Abhängigkeiten aktuell, SBOM | ✅ | Dependabot, Syft-SBOM, cosign im Release |
| V14.3 | Container gehärtet | ✅ | Non-root, read-only, Capabilities gedroppt, Trivy/Hadolint |

Offene Punkte für Betreiber: MFA-Richtlinie im IdP, TLS-Terminierung, Netzwerksegmentierung
der Datenbank, Export des Audit-Logs auf unveränderlichen Speicher.

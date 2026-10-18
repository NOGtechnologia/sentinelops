# Herkunft der kuratierten SigmaHQ-Regeln

| Datei | Quelle (Pfad im Repository SigmaHQ/sigma) | Autor (laut Regel) |
|---|---|---|
| `win_security_audit_log_cleared.yml` | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | Florian Roth (Nextron Systems) |
| `win_security_user_added_to_local_administrators.yml` | `rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml` | Florian Roth (Nextron Systems) |
| `lnx_privileged_user_creation.yml` | `rules/linux/builtin/lnx_privileged_user_creation.yml` | Pawel Mazur |

- Repository: <https://github.com/SigmaHQ/sigma>
- Commit: `b7920ed31356fb7f6a9275b34737d8604c65bac3` (Branch `master`)
- Abgerufen: 2026-10-18
- Lizenz: **Detection Rule License (DRL) 1.1** – Text in [`LICENSE`](LICENSE), Original:
  <https://github.com/SigmaHQ/Detection-Rule-License>
- Die Dateien sind **unverändert**. SentinelOps-spezifische Metadaten (Regel-ID,
  deutsche Titel, Playbook-Verweise) stehen getrennt in [`curation.yaml`](curation.yaml).
- Gemäß DRL 1.1 nennt jeder Alarm aus diesen Regeln den Autor (`author`) und die Quelle (siehe Alarmdetail und Bericht).

## Auswahlkriterien

Nur Regeln, die (1) mit dem kanonischen Schema bzw. der Processing-Pipeline
`rules/pipelines/sentinelops.yml` auswertbar sind, (2) ausschließlich unterstützte
Sigma-Features verwenden und (3) ihre Tests unter `rules/tests/` sowie den
Benchmark (Precision ≥ 0,90) bestehen.

Geprüft und **nicht** übernommen (Stand Phase 0):

| Regel | Grund |
|---|---|
| `win_security_member_added_security_enabled_global_group.yml` | Trifft jede Gruppenänderung (auch normale IT-Arbeit) – Precision im Benchmark < 0,90 |
| `win_security_user_creation.yml` | Laut Regel nur für Server ohne AD sinnvoll; Fehlalarme auf Domänencontrollern |
| `win_security_susp_failed_logon_source.yml` | Ein Alarm pro Fehlanmeldung; durch SO-AUTH-001/-002 besser abgedeckt |
| `win_security_explicit_credential_local_logon.yml` | Status `experimental`, Felder (TargetServerName/TargetInfo) im V1-Schema nicht normalisiert |
| `win_security_susp_failed_logon_reasons.yml` | Nutzt Status-Codes, die der Generator nicht abbildet – ohne aussagekräftige Tests |
| `lnx_sshd_susp_ssh.yml`, `lnx_clear_syslog.yml` | Keine passenden Testdaten/Szenarien in V1 |

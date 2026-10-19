# Erkennungskatalog

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


| Regel-ID | Version | Titel | Art | Schweregrad | Reifegrad | ATT&CK | Playbook | Quelle |
|---|---:|---|---|---|---|---|---|---|
| `SIGMAHQ-0AC15EC3` | 1 | Privilegierter Linux-Benutzer angelegt (SigmaHQ) | single | high | test | privilege-escalation, persistence, T1136.001, T1098 | REVIEW_GROUP_MEMBERSHIP, VERIFY_ACCOUNT_ACTIVITY, ISOLATE_HOST | sigmahq (`sigma/sigmahq/lnx_privileged_user_creation.yml`) |
| `SIGMAHQ-C265CF08` | 1 | Benutzer zur lokalen Administratorengruppe hinzugefügt (SigmaHQ) | single | medium | stable | initial-access, privilege-escalation, stealth, persistence, T1078, T1098 | REVIEW_GROUP_MEMBERSHIP, VERIFY_ACCOUNT_ACTIVITY | sigmahq (`sigma/sigmahq/win_security_user_added_to_local_administrators.yml`) |
| `SIGMAHQ-D99B79D2` | 1 | Sicherheitsprotokoll gelöscht (SigmaHQ) | single | high | test | defense-impairment, T1685.005 | ISOLATE_HOST, COLLECT_ADDITIONAL_LOGS | sigmahq (`sigma/sigmahq/win_security_audit_log_cleared.yml`) |
| `SO-ACC-001` | 1 | Konto angelegt und kurz darauf gelöscht | correlation | medium | stable | persistence, stealth, T1136.002, T1070 | VERIFY_ACCOUNT_ACTIVITY, REVIEW_GROUP_MEMBERSHIP, COLLECT_ADDITIONAL_LOGS | custom (`correlations/so-acc-001.yml`) |
| `SO-ACC-002` | 1 | Passwort-Reset durch fremdes Konto | single | high | stable | persistence, T1098 | VERIFY_ACCOUNT_ACTIVITY, RESET_PASSWORD, DISABLE_ACCOUNT | custom (`sigma/custom/so-acc-002.yml`) |
| `SO-AUTH-001` | 1 | Brute Force auf ein Konto | correlation | high | stable | credential-access, T1110.001 | VERIFY_ACCOUNT_ACTIVITY, BLOCK_SOURCE_IP, RESET_PASSWORD, COLLECT_ADDITIONAL_LOGS | custom (`correlations/so-auth-001.yml`) |
| `SO-AUTH-002` | 1 | Password Spraying | correlation | high | stable | credential-access, T1110.003 | BLOCK_SOURCE_IP, VERIFY_ACCOUNT_ACTIVITY, COLLECT_ADDITIONAL_LOGS | custom (`correlations/so-auth-002.yml`) |
| `SO-AUTH-003` | 1 | Erfolgreiche Anmeldung nach Brute Force | sequence | high | stable | credential-access, initial-access, T1110, T1078 | DISABLE_ACCOUNT, RESET_PASSWORD, VERIFY_ACCOUNT_ACTIVITY, ISOLATE_HOST, BLOCK_SOURCE_IP | custom (`correlations/so-auth-003.yml`) |
| `SO-AUTH-004` | 1 | Gehäufte Kontosperrungen | correlation | medium | stable | credential-access, impact, T1110, T1531 | COLLECT_ADDITIONAL_LOGS, VERIFY_ACCOUNT_ACTIVITY, BLOCK_SOURCE_IP | custom (`correlations/so-auth-004.yml`) |
| `SO-AUTH-005` | 1 | Ungewöhnliche Anmeldung | baseline | medium | test | initial-access, T1078 | VERIFY_ACCOUNT_ACTIVITY, COLLECT_ADDITIONAL_LOGS, RESET_PASSWORD | custom (`baselines/so-auth-005.yml`) |
| `SO-AUTH-006` | 1 | Laterale Bewegung | correlation | high | stable | lateral-movement, T1021.002, T1078 | ISOLATE_HOST, DISABLE_ACCOUNT, VERIFY_ACCOUNT_ACTIVITY, COLLECT_ADDITIONAL_LOGS | custom (`correlations/so-auth-006.yml`) |
| `SO-AUTH-007` | 1 | Konto gesperrt | single | low | stable | credential-access, T1110 | VERIFY_ACCOUNT_ACTIVITY | custom (`sigma/custom/so-auth-007.yml`) |
| `SO-DEF-001` | 1 | Sicherheitsprotokoll gelöscht | single | high | stable | defense-impairment, T1685.005 | ISOLATE_HOST, COLLECT_ADDITIONAL_LOGS, VERIFY_ACCOUNT_ACTIVITY | custom (`sigma/custom/so-def-001.yml`) |
| `SO-PRIV-001` | 1 | Aufnahme in privilegierte Gruppe | single | critical | stable | persistence, privilege-escalation, T1098 | REVIEW_GROUP_MEMBERSHIP, DISABLE_ACCOUNT, VERIFY_ACCOUNT_ACTIVITY, RESET_PASSWORD | custom (`sigma/custom/so-priv-001.yml`) |
| `SO-PRIV-002` | 1 | Sonderrechte für unerwartetes Konto | single | high | stable | privilege-escalation, T1078.002 | VERIFY_ACCOUNT_ACTIVITY, REVIEW_GROUP_MEMBERSHIP, DISABLE_ACCOUNT | custom (`sigma/custom/so-priv-002.yml`) |
| `SO-PRIV-003` | 1 | Wiederholte sudo-/su-Fehlschläge | correlation | high | stable | privilege-escalation, T1548.003 | VERIFY_ACCOUNT_ACTIVITY, DISABLE_ACCOUNT, ISOLATE_HOST | custom (`correlations/so-priv-003.yml`) |

## SIGMAHQ-0AC15EC3 – Privilegierter Linux-Benutzer angelegt (SigmaHQ)

Ein neuer Linux-Benutzer mit UID/GID 0 oder in den Gruppen wheel/sudo wurde angelegt (SigmaHQ-Regel).

*Privileged User Has Been Created* – Detects the addition of a new user to a privileged group such as "root" or "sudo"

- Bekannte Fehlalarmquellen: Administrative activity

- Autor: Pawel Mazur – Lizenz: Detection Rule License 1.1 (SigmaHQ)

## SIGMAHQ-C265CF08 – Benutzer zur lokalen Administratorengruppe hinzugefügt (SigmaHQ)

Ein Mitglied wurde der lokalen Gruppe Administratoren hinzugefügt (SigmaHQ-Regel).

*User Added to Local Administrator Group* – Detects the addition of a new member to the local administrator group, which could be legitimate activity or a sign of privilege escalation activity

- Bekannte Fehlalarmquellen: Legitimate administrative activity

- Autor: Florian Roth (Nextron Systems) – Lizenz: Detection Rule License 1.1 (SigmaHQ)

## SIGMAHQ-D99B79D2 – Sicherheitsprotokoll gelöscht (SigmaHQ)

Ein Windows-Ereignisprotokoll wurde gelöscht (SigmaHQ-Regel).

*Security Eventlog Cleared* – One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution

- Bekannte Fehlalarmquellen: Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)

- Autor: Florian Roth (Nextron Systems) – Lizenz: Detection Rule License 1.1 (SigmaHQ)

## SO-ACC-001 – Konto angelegt und kurz darauf gelöscht

Ein Benutzerkonto wird angelegt und kurz darauf wieder gelöscht.

*Account created and deleted shortly afterwards* – A user account is created and deleted again within a short time window (temporary attacker account).

- Korrelation: `temporal_ordered` über `so_helper_user_created`, `so_helper_user_deleted`; Gruppierung `user.target.name`; Bedingung gte 2; Zeitfenster 3600 s

- Bekannte Fehlalarmquellen: Provisioning errors corrected immediately by IT

## SO-ACC-002 – Passwort-Reset durch fremdes Konto

Das Passwort eines Kontos wurde von einem anderen Konto zurückgesetzt, das kein erwarteter Passwort-Administrator ist.

*Password reset by another, non-administrative account* – The password of an account was reset by a different account that is not an expected password administrator (placeholder password_admins).

- Bekannte Fehlalarmquellen: Delegated helpdesk accounts that are not on the password_admins list

## SO-AUTH-001 – Brute Force auf ein Konto

Viele fehlgeschlagene Anmeldungen für ein Konto in kurzer Zeit.

*Brute force against a single account* – Many failed logons for one account within a short time window (Windows 4625, SSH, VPN).

- Korrelation: `event_count` über `so_helper_logon_failed`; Gruppierung `user.name`; Bedingung gte 15; Zeitfenster 600 s

- Bekannte Fehlalarmquellen: Misconfigured service or script with an outdated password; User repeatedly mistyping after a password change (usually spread over a longer time)

## SO-AUTH-002 – Password Spraying

Eine Quell-IP mit Fehlanmeldungen für viele verschiedene Benutzer in kurzer Zeit.

*Password spraying from one source address* – One source IP fails to log on with many different accounts within a short time window.

- Korrelation: `value_count` über `so_helper_logon_failed_with_ip`; Gruppierung `source.ip`; Bedingung gte 10 verschiedene `user.name`; Zeitfenster 600 s

- Bekannte Fehlalarmquellen: Shared NAT address of many users with an authentication problem (e.g. expired certificate)

## SO-AUTH-003 – Erfolgreiche Anmeldung nach Brute Force

Erfolgreiche Anmeldung eines Kontos kurz nach Brute Force oder Password Spraying gegen dieses Konto.

*Successful logon after brute force or password spraying* – A successful logon of an account that was the target of a brute force or password spraying attack shortly before.

- Bekannte Fehlalarmquellen: The legitimate user logs on after a brute force attempt against their account

## SO-AUTH-004 – Gehäufte Kontosperrungen

Mehrere Kontosperrungen in kurzer Zeit.

*Many account lockouts* – Several account lockouts within a short time window (possible password spraying or a broken service).

- Korrelation: `event_count` über `so_helper_account_locked`; Gruppierung –; Bedingung gte 3; Zeitfenster 1800 s

- Bekannte Fehlalarmquellen: Domain-wide password policy change

## SO-AUTH-005 – Ungewöhnliche Anmeldung

Erfolgreiche Anmeldung, die vom gelernten Profil des Benutzers abweicht (neues Netz, neues Zielgerät, ungewöhnliche Uhrzeit, Wochenende/Feiertag).

*Unusual logon (first-time network, host or time)* – Successful interactive or remote logon that deviates from the user's learned profile (new network, new target host, unusual time, weekend/holiday).

- Bekannte Fehlalarmquellen: Business travel, new workstation, overtime

## SO-AUTH-006 – Laterale Bewegung

Ein Konto meldet sich per Netzwerk-Logon in kurzer Zeit an vielen verschiedenen Hosts an.

*Lateral movement - one account logs on to many hosts* – An account performs network logons to many different hosts within a short time window.

- Korrelation: `value_count` über `so_helper_network_logon`; Gruppierung `user.name`; Bedingung gte 5 verschiedene `host.name`; Zeitfenster 1800 s

- Bekannte Fehlalarmquellen: Monitoring, inventory or backup service accounts (add an exception); Administrators deploying software

## SO-AUTH-007 – Konto gesperrt

Ein Konto wurde nach zu vielen Fehlanmeldungen gesperrt. Meist Tippfehler des Benutzers.

*Account locked out* – A single account was locked out after too many failed logons. Usually a user mistyping the password; low severity on its own.

- Bekannte Fehlalarmquellen: Users mistyping their password, typically after a password change

## SO-DEF-001 – Sicherheitsprotokoll gelöscht

Das Windows-Sicherheitsprotokoll wurde gelöscht (Ereignis 1102).

*Security event log cleared* – The Windows Security event log was cleared (event 1102), a typical step to remove traces.

- Bekannte Fehlalarmquellen: Rollout of log collection agents or system provisioning

## SO-PRIV-001 – Aufnahme in privilegierte Gruppe

Ein Konto wurde einer privilegierten Gruppe hinzugefügt (z. B. Domänen-Admins, Administratoren, sudo, wheel).

*Member added to a privileged group* – An account was added to a privileged group (Domain Admins, Administrators, sudo, wheel, ...). The group list is configurable (placeholder privileged_groups).

- Bekannte Fehlalarmquellen: Planned onboarding of a new administrator (verify the change ticket)

## SO-PRIV-002 – Sonderrechte für unerwartetes Konto

Sonderrechte (Ereignis 4672) für ein Konto außerhalb der erwarteten Admin-Liste.

*Special privileges assigned to an unexpected account* – Windows event 4672 (special privileges assigned to new logon) for an account that is not on the list of expected privileged accounts (placeholder expected_privileged_accounts).

- Bekannte Fehlalarmquellen: New administrator not yet added to the expected account list

## SO-PRIV-003 – Wiederholte sudo-/su-Fehlschläge

Mehrere fehlgeschlagene sudo- oder su-Versuche eines Kontos in kurzer Zeit.

*Repeated sudo or su failures* – Several failed sudo or su attempts of one account within a short time window (Linux privilege escalation attempt).

- Korrelation: `event_count` über `so_helper_linux_privesc_failure`; Gruppierung `user.name`; Bedingung gte 3; Zeitfenster 600 s

- Bekannte Fehlalarmquellen: Administrator mistyping the password several times

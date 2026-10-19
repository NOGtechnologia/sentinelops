# Belege und Fehlalarme

## Belege prüfen

![Belege: Regel-YAML mit hervorgehobener Bedingung, passende Felder und Rohzeilen](../images/case-evidence-dark.png)

Für jeden Alarm des Falls zeigt der Bereich **Belege**:

1. **Regel (Sigma-YAML)** – die Bedingung und die greifenden Detection-Items sind hervorgehoben;
   Version, Autor, Herkunft und Lizenz stehen im Kopf.
2. **Treffererklärung** – bei Einzelregeln die passenden Felder mit erwartetem und tatsächlichem Wert
   sowie nicht zutreffende Filter; bei Korrelationen Bedingung, beobachteter Wert und Gruppierung;
   bei Baselines die erfüllten Kriterien (neues Netz, ungewöhnliche Uhrzeit, …).
3. **Belege E1…En** – wichtige normalisierte Felder und die **unveränderte Rohzeile**. Werte, die zum
   Treffer geführt haben, sind markiert. Rohzeilen werden immer als Text angezeigt – auch wenn sie
   HTML oder Skripte enthalten.

## Als Fehlalarm markieren

„Als Fehlalarm markieren“ verlangt einen Grund. Die Markierung erscheint am Alarm, fließt in die
Fehlalarmquote der Regel ein (die wiederum die Priorität künftiger Fälle senken kann) und steht im
Audit-Log. Den Fallstatus setzen Sie separat (z. B. „Erledigt: Fehlalarm“).

## Ausnahme vorschlagen

„Ausnahme vorschlagen“ legt eine befristete, begründete Ausnahme an (z. B. „Dienstkonto svc_backup
auf srv-backup01 ist erwartet“). Die Bedingung ist mit der Gruppierung des Alarms bzw. dem betroffenen
Benutzer vorbelegt und kann angepasst werden. Ausnahmen werden erst wirksam, wenn eine **andere**
Person mit Rolle L2 sie genehmigt (Vier-Augen-Prinzip); danach läuft die Analyse automatisch neu.

Dieser Ablauf ist Abnahmetest A4 und wird in jeder CI geprüft (`e2e/a4_false_positive.spec.ts`).

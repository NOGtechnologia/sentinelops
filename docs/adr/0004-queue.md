# ADR-0004: Job-Queue in PostgreSQL

## Kontext

Ingestion, Analyse und Aufbewahrung laufen asynchron. Die Spezifikation verlangt eine
PostgreSQL-basierte Queue ohne zusätzlichen Broker und nennt `procrastinate` als Beispiel.

## Entscheidung

Eine **eigene, kleine Queue** in der Tabelle `jobs` (`storage/jobs.py`):
`SELECT … FOR UPDATE SKIP LOCKED`, bis zu drei Versuche mit linearem Backoff, Status
`queued/running/done/failed`, Deduplizierung gleichartiger wartender Jobs (z. B. „analyze“).
Jobs sind idempotent (Analyse berechnet deterministische Ergebnisse neu), daher genügt
At-least-once.

## Alternativen

- `procrastinate`: ausgereift, bringt aber eigenes Schema, eigene Worker-Prozesse und
  Psycopg-Abhängigkeit neben asyncpg. Für drei Job-Arten unverhältnismäßig.
- Redis/RabbitMQ/Celery: zusätzlicher Dienst, ausgeschlossen durch die Spezifikation.

## Konsequenzen

~70 Zeilen eigener Code mit Integrationstests (Claim, Retry, Fehlerstatus). Kein Scheduling
außer dem täglichen Aufbewahrungs-Job, den der Worker selbst einreiht.

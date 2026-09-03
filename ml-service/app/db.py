"""
DB access for the ML service. Reads ONLY the `security_events` table
(THREAT_MODEL.md §4.6/§8) — allow-listed telemetry fields, never content,
plaintext, or credentials. This service has no reason to and does not
query any other table.
"""
import os
import psycopg
from psycopg.rows import dict_row


def _normalized_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "postgresql://phantomvault:phantomvault@localhost:5432/phantomvault")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def get_connection() -> psycopg.Connection:
    return psycopg.connect(_normalized_database_url(), row_factory=dict_row)

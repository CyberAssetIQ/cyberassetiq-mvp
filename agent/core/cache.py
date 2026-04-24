from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class LocalQueue:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()

    def enqueue(self, payload_type: str, payload: dict[str, Any], max_queue_size: int = 500) -> None:
        with self._connect() as conn:
            # Prune oldest entries if queue is at capacity to prevent unbounded growth
            count = conn.execute("SELECT COUNT(*) FROM outbound_queue").fetchone()[0]
            if count >= max_queue_size:
                conn.execute(
                    "DELETE FROM outbound_queue WHERE id IN "
                    "(SELECT id FROM outbound_queue ORDER BY id ASC LIMIT ?)",
                    (max(1, count - max_queue_size + 1),),
                )
            conn.execute(
                """
                INSERT INTO outbound_queue (payload_type, payload_json, created_at, retry_count)
                VALUES (?, ?, ?, 0)
                """,
                (payload_type, json.dumps(payload), int(time.time())),
            )
            conn.commit()

    def prune_stale(self, max_age_seconds: int = 86400) -> int:
        """Remove entries older than max_age_seconds that have failed repeatedly."""
        cutoff = int(time.time()) - max_age_seconds
        with self._connect() as conn:
            result = conn.execute(
                "DELETE FROM outbound_queue WHERE created_at < ? AND retry_count >= 5",
                (cutoff,),
            )
            conn.commit()
            return result.rowcount

    def get_batch(self, limit: int = 50) -> list[tuple[int, str, dict[str, Any], int]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, payload_type, payload_json, retry_count
                FROM outbound_queue
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        result = []
        for row in rows:
            result.append((row[0], row[1], json.loads(row[2]), row[3]))
        return result

    def delete(self, row_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_queue WHERE id = ?", (row_id,))
            conn.commit()

    def increment_retry(self, row_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE outbound_queue SET retry_count = retry_count + 1 WHERE id = ?",
                (row_id,),
            )
            conn.commit()

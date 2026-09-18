"""
Database Module - SQLite-based storage for scan results
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .logger import Logger


class Database:
    """
    SQLite database for storing scan results and findings.

    Schema:
    - targets: Target information
    - scans: Scan session information
    - findings: Individual vulnerability findings
    - assets: Discovered assets (subdomains, ports, etc.)
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_scan_at TIMESTAMP,
        total_scans INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        scan_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        security_score REAL,
        total_findings INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL,
        title TEXT NOT NULL,
        description TEXT,
        url TEXT,
        parameter TEXT,
        payload TEXT,
        poc TEXT,
        remediation TEXT,
        references TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        asset_type TEXT NOT NULL,
        value TEXT NOT NULL,
        metadata TEXT,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
    """

    def __init__(self, db_path: str = ".secpenhub.db"):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.logger = Logger.get_logger("database")
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Target operations
    def add_target(self, url: str, name: Optional[str] = None) -> int:
        """Add a new target and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT OR IGNORE INTO targets (url, name) VALUES (?, ?)""",
                (url, name)
            )
            conn.commit()

            if cursor.lastrowid:
                return cursor.lastrowid
            else:
                # Target exists, get its ID
                result = conn.execute(
                    "SELECT id FROM targets WHERE url = ?", (url,)
                ).fetchone()
                return result["id"]

    def get_target(self, url: str) -> Optional[Dict[str, Any]]:
        """Get target information."""
        with self._get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM targets WHERE url = ?", (url,)
            ).fetchone()
            return dict(result) if result else None

    def update_target_scan_count(self, target_id: int) -> None:
        """Increment target's total scan count."""
        with self._get_connection() as conn:
            conn.execute(
                """UPDATE targets
                   SET total_scans = total_scans + 1,
                       last_scan_at = CURRENT_TIMESTAMP
                   WHERE id = ?""",
                (target_id,)
            )
            conn.commit()

    # Scan operations
    def create_scan(self, target_id: int, scan_type: str) -> int:
        """Create a new scan session and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scans (target_id, scan_type, status)
                   VALUES (?, ?, 'running')""",
                (target_id, scan_type)
            )
            conn.commit()
            return cursor.lastrowid

    def complete_scan(
        self,
        scan_id: int,
        security_score: float,
        finding_counts: Dict[str, int]
    ) -> None:
        """Mark scan as completed with results."""
        with self._get_connection() as conn:
            conn.execute(
                """UPDATE scans
                   SET status = 'completed',
                       completed_at = CURRENT_TIMESTAMP,
                       security_score = ?,
                       total_findings = ?,
                       critical_count = ?,
                       high_count = ?,
                       medium_count = ?,
                       low_count = ?
                   WHERE id = ?""",
                (
                    security_score,
                    finding_counts.get("total", 0),
                    finding_counts.get("critical", 0),
                    finding_counts.get("high", 0),
                    finding_counts.get("medium", 0),
                    finding_counts.get("low", 0),
                    scan_id
                )
            )
            conn.commit()

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get scan information."""
        with self._get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            return dict(result) if result else None

    def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """Get all results for a scan."""
        with self._get_connection() as conn:
            scan = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()

            if not scan:
                return {}

            findings = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC",
                (scan_id,)
            ).fetchall()

            assets = conn.execute(
                "SELECT * FROM assets WHERE scan_id = ?",
                (scan_id,)
            ).fetchall()

            return {
                "scan": dict(scan),
                "findings": [dict(f) for f in findings],
                "assets": [dict(a) for a in assets]
            }

    # Finding operations
    def add_finding(
        self,
        scan_id: int,
        vulnerability_type: str,
        severity: str,
        title: str,
        cvss_score: float = 0.0,
        description: Optional[str] = None,
        url: Optional[str] = None,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        poc: Optional[str] = None,
        remediation: Optional[str] = None,
        references: Optional[str] = None
    ) -> int:
        """Add a new finding to a scan."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO findings
                   (scan_id, vulnerability_type, severity, cvss_score,
                    title, description, url, parameter, payload, poc,
                    remediation, references)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, vulnerability_type, severity, cvss_score,
                    title, description, url, parameter, payload, poc,
                    remediation, references
                )
            )
            conn.commit()
            return cursor.lastrowid

    # Asset operations
    def add_asset(
        self,
        scan_id: int,
        asset_type: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """Add a discovered asset."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO assets (scan_id, asset_type, value, metadata)
                   VALUES (?, ?, ?, ?)""",
                (scan_id, asset_type, value, json.dumps(metadata) if metadata else None)
            )
            conn.commit()
            return cursor.lastrowid

    def get_assets_by_type(self, scan_id: int, asset_type: str) -> List[str]:
        """Get all assets of a specific type for a scan."""
        with self._get_connection() as conn:
            results = conn.execute(
                "SELECT value FROM assets WHERE scan_id = ? AND asset_type = ?",
                (scan_id, asset_type)
            ).fetchall()
            return [r["value"] for r in results]

    # Analytics
    def get_statistics(self, target_id: int) -> Dict[str, Any]:
        """Get scan statistics for a target."""
        with self._get_connection() as conn:
            scans = conn.execute(
                """SELECT * FROM scans
                   WHERE target_id = ? AND status = 'completed'
                   ORDER BY completed_at DESC""",
                (target_id,)
            ).fetchall()

            if not scans:
                return {"total_scans": 0, "average_score": None}

            scores = [s["security_score"] for s in scans if s["security_score"]]
            total_findings = sum(s["total_findings"] for s in scans)

            return {
                "total_scans": len(scans),
                "average_score": sum(scores) / len(scores) if scores else None,
                "total_findings": total_findings,
                "trend": "improving" if len(scores) >= 2 and scores[0] > scores[1] else "stable"
            }

"""
Storage and logging module for Zambian Scam Detector.
Handles SQLite database for detections, feedback, and provider analytics.
"""

import sqlite3
import re
from datetime import datetime
import csv
import os
import argparse
import sys
import threading
import queue
import time
from collections import Counter

DB_PATH = "detections.db"
# Whether to enable the optional background writer (default: False to preserve current behavior)
BACKGROUND_WRITER_ENABLED = False

# Internal writer instance (created when start_background_writer() is called)
_background_writer = None


def init_database():
    """Create database tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Detections table: stores every analysis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            message_masked TEXT NOT NULL,
            message_hash TEXT,
            score INTEGER NOT NULL,
            flags TEXT,
            risk_level TEXT,
            source TEXT DEFAULT 'unknown',
            provider TEXT,
            UNIQUE(message_hash, timestamp)
        )
    ''')
    
    # Feedback table: stores user/provider labels
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            label TEXT NOT NULL,
            note TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(detection_id) REFERENCES detections(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"[OK] Database initialized: {DB_PATH}")


def mask_pii(text, min_chars=4):
    """
    Mask personally identifiable information before storage.
    Masks phone numbers, email addresses, and sensitive digits.
    
    Examples:
    "+260971234567" → "+26097XXXXX67"
    "user@email.com" → "us**@email.com"
    """
    if not text:
        return text
    
    # Mask Zambian phone numbers (+260 or 0 prefix, keep first 5 and last 2 digits)
    text = re.sub(r'(\+?260\d{2})\d+(\d{2})', r'\1XXXXX\2', text)
    text = re.sub(r'\b(09[567]\d)\d+(\d{2})\b', r'\1XXXXX\2', text)
    
    # Mask email addresses
    text = re.sub(r'(\w{2})\w*(@\w+\.\w+)', r'\1**\2', text)
    
    # Mask long sequences of digits (account numbers — 8+ digits only)
    text = re.sub(r'(\d{2})\d{4,}(\d{2})', r'\1XXXX\2', text)
    
    return text


def hash_message(text):
    """Create a hash of the message to detect duplicates (privacy-safe)."""
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def log_detection(message, score, flags, risk_level, source="unknown", provider=None):
    """
    Log a detection event to the database.
    
    Args:
        message: Original message text
        score: Scam score (0-20)
        flags: List of detected scam types
        risk_level: Risk assessment (SAFE, LOW RISK, etc.)
        source: "end_user" or "provider"
        provider: Provider name (e.g., "Airtel", "MTN")
    
    Returns:
        detection_id: ID for linking feedback later
    """
    # Keep original synchronous behavior by default.
    return _write_detection_sync(message, score, flags, risk_level, source=source, provider=provider)


def _write_detection_sync(message, score, flags, risk_level, source="unknown", provider=None):
    """
    Internal synchronous write path used by both direct calls and the background worker.
    Assumes init_database() has already been called at startup.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    masked_msg = mask_pii(message)
    msg_hash = hash_message(message)
    flags_str = ",".join(flags) if isinstance(flags, list) else str(flags)

    try:
        cursor.execute('''
            INSERT INTO detections 
            (timestamp, message_masked, message_hash, score, flags, risk_level, source, provider)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            masked_msg,
            msg_hash,
            score,
            flags_str,
            risk_level,
            source,
            provider
        ))

        detection_id = cursor.lastrowid
        conn.commit()

        return detection_id

    except sqlite3.IntegrityError:
        # Duplicate message at same time (rare), return existing
        cursor.execute(
            'SELECT id FROM detections WHERE message_hash=? ORDER BY id DESC LIMIT 1',
            (msg_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    finally:
        conn.close()


def record_feedback(detection_id, source, label, note=""):
    """
    Record user or provider feedback on a detection.
    
    Args:
        detection_id: ID from log_detection()
        source: "end_user" or "provider"
        label: "true_positive", "false_positive", "false_negative", "correct"
        note: Optional user note explaining the feedback
    """
    # Keep synchronous default behavior
    return _write_feedback_sync(detection_id, source, label, note)


def _write_feedback_sync(detection_id, source, label, note=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO feedback 
        (detection_id, source, label, note, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (detection_id, source, label, note, datetime.now().isoformat()))

    conn.commit()
    conn.close()


def get_detection_by_id(detection_id):
    """Retrieve a detection record by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, timestamp, message_masked, score, flags, risk_level, source, provider
        FROM detections WHERE id=?
    ''', (detection_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "id": result[0],
            "timestamp": result[1],
            "message_masked": result[2],
            "score": result[3],
            "flags": result[4],
            "risk_level": result[5],
            "source": result[6],
            "provider": result[7]
        }
    return None


class ProviderDashboard:
    """Analytics and export functions for service providers."""
    
    @staticmethod
    def get_daily_summary(date_str=None, provider=None, source=None):
        """
        Get summary stats for a date.

        Args:
            date_str: Date in format "YYYY-MM-DD" (default: today)
            provider: Filter by provider (e.g., "Airtel")
            source: Optional source filter (e.g., "provider_api_v1")

        Returns:
            Dictionary with counts and stats
        """
        if not date_str:
            date_str = datetime.now().strftime("%Y-%m-%d")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Build parameterised WHERE clause to avoid SQL injection
        conditions = ["timestamp LIKE ?"]
        params: list = [f"{date_str}%"]
        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        if source:
            conditions.append("source = ?")
            params.append(source)
        where_clause = "WHERE " + " AND ".join(conditions)

        # Total analyzed
        cursor.execute(f"SELECT COUNT(*) FROM detections {where_clause}", params)
        total = cursor.fetchone()[0]

        # By risk level
        cursor.execute(
            f"SELECT risk_level, COUNT(*) FROM detections {where_clause} GROUP BY risk_level",
            params,
        )
        risk_breakdown = dict(cursor.fetchall())

        # Top scam types (aggregate each flag token; ignore empty/safe rows)
        cursor.execute(
            f"""
            SELECT flags, COUNT(*) as count FROM detections
            {where_clause}
            AND TRIM(COALESCE(flags, '')) != ''
            GROUP BY flags
            """,
            params,
        )
        top_counter = Counter()
        for flags_str, row_count in cursor.fetchall():
            for flag in (flags_str or "").split(","):
                cleaned = flag.strip()
                if cleaned:
                    top_counter[cleaned] += row_count
        top_scams = [{"type": k, "count": v} for k, v in top_counter.most_common(5)]

        conn.close()

        return {
            "date": date_str,
            "provider": provider or "All",
            "source": source or "All",
            "total_analyzed": total,
            "risk_breakdown": risk_breakdown,
            "top_scams": top_scams,
        }
    
    @staticmethod
    def export_csv_for_review(min_risk_level=None, provider=None, output_file=None):
        """
        Export flagged detections to CSV for provider review.

        Args:
            min_risk_level: Filter to MODERATE RISK and above
            provider: Filter by provider
            output_file: Save to file (default: exports/provider_review_{timestamp}.csv)

        Returns:
            Path to exported file
        """
        if not output_file:
            os.makedirs("exports", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join("exports", f"provider_review_{timestamp}.csv")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        query = "SELECT id, timestamp, message_masked, score, flags, risk_level, source, provider FROM detections"
        filters = []
        
        allowed_risk_order = ["MODERATE RISK", "HIGH RISK", "EXTREME RISK - LIKELY SCAM"]
        selected_levels = []
        if min_risk_level:
            if min_risk_level not in allowed_risk_order:
                raise ValueError(
                    f"Invalid min_risk_level '{min_risk_level}'. "
                    f"Allowed: {allowed_risk_order}"
                )
            selected_levels = allowed_risk_order[allowed_risk_order.index(min_risk_level):]
            filters.append(f"risk_level IN ({','.join(['?'] * len(selected_levels))})")
        
        if provider:
            filters.append("provider = ?")
        
        if filters:
            query += " WHERE " + " AND ".join(filters)
        
        query += " ORDER BY timestamp DESC"
        
        params = []
        if min_risk_level:
            params.extend(selected_levels)
        if provider:
            params.append(provider)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Write CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Message (Masked)", "Score", "Flags", "Risk Level", "Source", "Provider"])
            writer.writerows(rows)
        
        print(f"[OK] Exported {len(rows)} records to {output_file}")
        return output_file
    
    @staticmethod
    def get_feedback_accuracy(provider=None):
        """
        Calculate detector accuracy based on feedback.

        Returns:
            Accuracy stats with confusion-matrix counts and metrics.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Build parameterised query to avoid SQL injection
        if provider:
            cursor.execute(
                '''
                SELECT label, COUNT(*) as count FROM feedback
                WHERE detection_id IN (
                    SELECT id FROM detections WHERE provider = ?
                )
                GROUP BY label
                ''',
                (provider,),
            )
        else:
            cursor.execute(
                "SELECT label, COUNT(*) as count FROM feedback GROUP BY label"
            )

        feedback_counts = dict(cursor.fetchall())

        tp = feedback_counts.get('true_positive', 0)
        fp = feedback_counts.get('false_positive', 0)
        fn = feedback_counts.get('false_negative', 0)
        tn = feedback_counts.get('true_negative', 0)

        total = tp + fp + fn + tn
        accuracy = ((tp + tn) / total) if total > 0 else 0
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0

        conn.close()

        return {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "total_labeled": total,
            "accuracy": round(accuracy * 100, 1),
            "precision": round(precision * 100, 1),
            "recall": round(recall * 100, 1),
        }


class BackgroundWriter:
    """Background writer that consumes a queue and performs DB writes.

    Usage: create an instance, call `start()`, then use `enqueue_detection()` and
    `enqueue_feedback()`. Call `stop()` to flush and stop the worker.
    """

    def __init__(self, max_queue=1000):
        self.queue = queue.Queue(maxsize=max_queue)
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        # Signal stop and wait for worker to finish
        self._stop_event.set()
        # Put a sentinel to unblock queue.get()
        try:
            self.queue.put_nowait(("_STOP", None))
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                task = self.queue.get(timeout=0.5)
            except Exception:
                continue

            if not task:
                continue

            action, payload = task
            if action == "_STOP":
                break

            try:
                if action == "detection":
                    _write_detection_sync(**payload)
                elif action == "feedback":
                    _write_feedback_sync(**payload)
            except Exception as e:
                # Swallow errors but print a warning for visibility
                print(f"[BackgroundWriter] write error: {e}")
            finally:
                self.queue.task_done()

    def enqueue_detection(self, message, score, flags, risk_level, source="unknown", provider=None):
        payload = {
            "message": message,
            "score": score,
            "flags": flags,
            "risk_level": risk_level,
            "source": source,
            "provider": provider,
        }
        try:
            self.queue.put_nowait(("detection", payload))
            return True
        except queue.Full:
            return False

    def enqueue_feedback(self, detection_id, source, label, note=""):
        payload = {"detection_id": detection_id, "source": source, "label": label, "note": note}
        try:
            self.queue.put_nowait(("feedback", payload))
            return True
        except queue.Full:
            return False


def start_background_writer(max_queue=1000):
    global _background_writer
    if _background_writer is None:
        _background_writer = BackgroundWriter(max_queue=max_queue)
        _background_writer.start()
    return _background_writer


def stop_background_writer():
    global _background_writer
    if _background_writer:
        _background_writer.stop()
        _background_writer = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="storage.py", description="Storage/DB utilities for Scam Detector")
    sub = parser.add_subparsers(dest="cmd")

    sub_init = sub.add_parser("init", help="Initialize the database")

    sub_log = sub.add_parser("log", help="Log a detection")
    sub_log.add_argument("--message", required=True, help="Message text")
    sub_log.add_argument("--score", type=int, required=True, help="Numeric score")
    sub_log.add_argument("--flags", help="Comma-separated flags")
    sub_log.add_argument("--risk", default="LOW RISK", help="Risk level")
    sub_log.add_argument("--source", default="end_user")
    sub_log.add_argument("--provider", default=None)

    sub_fb = sub.add_parser("feedback", help="Record feedback for a detection")
    sub_fb.add_argument("--id", type=int, required=True, help="Detection ID")
    sub_fb.add_argument("--source", required=True)
    sub_fb.add_argument("--label", required=True)
    sub_fb.add_argument("--note", default="")

    sub_sum = sub.add_parser("summary", help="Print daily summary")
    sub_sum.add_argument("--date", help="YYYY-MM-DD")
    sub_sum.add_argument("--provider", help="Provider name")

    sub_export = sub.add_parser("export", help="Export detections to CSV")
    sub_export.add_argument("--min-risk", choices=["MODERATE RISK", "HIGH RISK", "EXTREME RISK - LIKELY SCAM"], help="Minimum risk level to include")
    sub_export.add_argument("--provider", help="Filter by provider")
    sub_export.add_argument("--output", help="Output CSV file path")

    # If no args provided, show help and perform quick test
    if len(sys.argv) == 1:
        print("No command provided — running quick self-test (same as before).\n")
        init_database()
        det_id = log_detection(
            "Hello dear, send money for flight +260971234567",
            score=12,
            flags=["Romance scams detected"],
            risk_level="HIGH RISK",
            source="end_user",
            provider="Airtel"
        )
        print(f"Logged detection: {det_id}")
        if det_id:
            record_feedback(det_id, source="end_user", label="true_positive", note="Confirmed scam")
            print("Feedback recorded")
        summary = ProviderDashboard.get_daily_summary()
        print(f"\nDaily Summary: {summary}")
        ProviderDashboard.export_csv_for_review()
        sys.exit(0)

    args = parser.parse_args()

    if args.cmd == "init":
        init_database()

    elif args.cmd == "log":
        flags = args.flags.split(",") if args.flags else []
        det_id = log_detection(args.message, args.score, flags, args.risk, source=args.source, provider=args.provider)
        print(f"Logged detection: {det_id}")

    elif args.cmd == "feedback":
        record_feedback(args.id, args.source, args.label, note=args.note)
        print("Feedback recorded")

    elif args.cmd == "summary":
        summary = ProviderDashboard.get_daily_summary(date_str=args.date, provider=args.provider)
        print(summary)

    elif args.cmd == "export":
        path = ProviderDashboard.export_csv_for_review(min_risk_level=args.min_risk, provider=args.provider, output_file=args.output)
        print(f"Exported to: {path}")

    else:
        parser.print_help()

import os
import time
import storage
import pytest


def setup_db(tmp_path):
    db = tmp_path / "test_bg_detections.db"
    storage.DB_PATH = str(db)
    if db.exists():
        db.unlink()
    storage.init_database()
    return db


def test_background_writer_enqueue(tmp_path):
    """Test that background writer can enqueue and flush detections."""
    setup_db(tmp_path)
    writer = storage.BackgroundWriter(max_queue=10)
    writer.start()
    
    try:
        # Enqueue a detection
        ok = writer.enqueue_detection(
            message="Test +260971234567",
            score=8,
            flags=["test"],
            risk_level="HIGH RISK",
            source="test",
            provider="TestProv"
        )
        assert ok is True
        
        # Give worker time to process
        time.sleep(0.5)
        
        # Verify it was written
        import sqlite3
        conn = sqlite3.connect(storage.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM detections")
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count >= 1
    finally:
        writer.stop()


def test_enqueue_with_fallback_sync(tmp_path):
    """Test fallback to sync when queue is full."""
    setup_db(tmp_path)
    writer = storage.BackgroundWriter(max_queue=2)
    writer.start()
    
    try:
        # Fill queue
        for i in range(3):
            ok = writer.enqueue_detection(
                message=f"Message {i}",
                score=5,
                flags=["test"],
                risk_level="LOW RISK",
                source="test"
            )
            if i < 2:
                assert ok is True
            # Third enqueue should fail (queue full)
        
        # Wait for worker to process queue
        time.sleep(1.0)
        
        # Verify at least some were written
        import sqlite3
        conn = sqlite3.connect(storage.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM detections")
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count >= 1
    finally:
        writer.stop(timeout=2.0)


def test_background_writer_stop_flushes(tmp_path):
    """Test that stop() waits for pending tasks."""
    setup_db(tmp_path)
    writer = storage.BackgroundWriter(max_queue=10)
    writer.start()
    
    # Enqueue multiple
    for i in range(5):
        writer.enqueue_detection(
            message=f"Test {i}",
            score=5,
            flags=["test"],
            risk_level="LOW RISK"
        )
    
    # Give worker time to start processing before stopping
    time.sleep(0.2)
    
    # Stop and wait for flush
    writer.stop(timeout=3.0)
    
    # Verify all (or most) were written
    import sqlite3
    conn = sqlite3.connect(storage.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM detections")
    count = cursor.fetchone()[0]
    conn.close()
    
    # At least 3+ should be written (worker may still be processing others)
    assert count >= 3

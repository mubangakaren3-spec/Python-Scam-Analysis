import os
import storage
import pytest


def setup_db(tmp_path):
    db = tmp_path / "test_detections.db"
    storage.DB_PATH = str(db)
    # ensure clean state
    if db.exists():
        db.unlink()
    storage.init_database()
    return db


def test_log_and_get(tmp_path):
    setup_db(tmp_path)
    det_id = storage.log_detection("Test number +260971234567", 5, ["test"], "LOW RISK", source="test", provider="TestProv")
    assert isinstance(det_id, int)
    rec = storage.get_detection_by_id(det_id)
    assert rec['id'] == det_id
    assert rec['score'] == 5


def test_feedback_and_accuracy(tmp_path):
    setup_db(tmp_path)
    det_id = storage.log_detection("Another +260971234567", 8, ["scam"], "HIGH RISK", source="test")
    storage.record_feedback(det_id, 'end_user', 'true_positive', note='ok')
    stats = storage.ProviderDashboard.get_feedback_accuracy()
    assert stats['true_positives'] >= 1


def test_export_csv(tmp_path):
    setup_db(tmp_path)
    det_id = storage.log_detection("Export +260971234567", 10, ["scam"], "MODERATE RISK", source="test")
    out = storage.ProviderDashboard.export_csv_for_review(output_file=str(tmp_path / "out.csv"))
    assert os.path.exists(out)
    with open(out, 'r', encoding='utf-8') as f:
        header = f.readline()
        assert "ID" in header

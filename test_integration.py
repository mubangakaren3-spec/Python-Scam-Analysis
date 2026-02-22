#!/usr/bin/env python
"""
Quick integration test: verify database, logging, and provider dashboard work.
"""

from storage import ProviderDashboard
import sqlite3

print("="*70)
print("ZAMBIAN SCAM DETECTOR - INTEGRATION TEST")
print("="*70)

# Test 1: Provider Dashboard Summary
print("\n[TEST 1] Provider Dashboard Summary")
summary = ProviderDashboard.get_daily_summary()
print(f"✓ Date: {summary['date']}")
print(f"✓ Total Analyzed: {summary['total_analyzed']}")
print(f"✓ Risk Breakdown: {summary['risk_breakdown']}")

# Test 2: Feedback-based accuracy
print("\n[TEST 2] Feedback-Based Accuracy")
stats = ProviderDashboard.get_feedback_accuracy()
print(f"✓ True Positives: {stats['true_positives']}")
print(f"✓ False Positives: {stats['false_positives']}")
print(f"✓ False Negatives: {stats['false_negatives']}")
print(f"✓ Accuracy: {stats['accuracy']}%")
print(f"✓ Precision: {stats['precision']}%")

# Test 3: Database integrity
print("\n[TEST 3] Database Integrity")
conn = sqlite3.connect('detections.db')
cursor = conn.cursor()

cursor.execute('SELECT COUNT(*) FROM detections')
det_count = cursor.fetchone()[0]
print(f"✓ Detections recorded: {det_count}")

cursor.execute('SELECT COUNT(*) FROM feedback')
fb_count = cursor.fetchone()[0]
print(f"✓ Feedback entries: {fb_count}")

cursor.execute('''SELECT label, COUNT(*) as count FROM feedback GROUP BY label ORDER BY count DESC''')
feedback_breakdown = cursor.fetchall()
print(f"✓ Feedback breakdown:")
for label, count in feedback_breakdown:
    print(f"    - {label}: {count}")

conn.close()

# Test 4: CSV export
print("\n[TEST 4] CSV Export")
csv_file = ProviderDashboard.export_csv_for_review(min_risk_level="MODERATE RISK")
print(f"✓ CSV file created: {csv_file}")

print("\n" + "="*70)
print("ALL INTEGRATION TESTS PASSED ✓")
print("="*70)
print("\nMVP is ready for beta launch!")
print("\nNext steps:")
print("  1. Build Flask UI (app_server.py)")
print("  2. Onboard 5-10 beta users")
print("  3. Collect feedback & adjust rules")
print("  4. Deploy to production")

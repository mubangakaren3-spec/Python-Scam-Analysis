# Zambian Scam Detector - MVP

A dual-purpose scam detection system for **service providers** (Airtel, MTN, Banks) and **end-users** in Zambia.

---

## **Quick Start**

### **Run the detector (CLI)**
```bash
python App.py
```

This runs:
1. **Test suite** — analyzes 6 sample scam/legitimate messages
2. **Evaluation** — tests detector on 28 labeled messages  
3. **Provider dashboard** — shows summary stats
4. **Feedback recording** — stores all results in database
5. **CSV export** — generates report for provider review

### **Output**
- `detections.db` — SQLite database with all detections and feedback
- `provider_review_[timestamp].csv` — CSV export of flagged messages for provider review

---

## **Architecture**

### **Core Files**

| File | Purpose |
|------|---------|
| `App.py` | Main detector logic, test suite, evaluation |
| `Test_detector.py` | Unit tests (future) |
| `storage.py` | Database + logging + provider analytics |
| `detections.db` | SQLite database for persistence |

### **How It Works**

```
Message Input
    ↓
ScamDetector.analyze() → Score + Flags
    ↓
ScamDetector.get_risk_level() → Risk (SAFE / LOW / MODERATE / HIGH / EXTREME)
    ↓
ScamDetector.get_advice() → Zambian-specific safety advice
    ↓
log_detection() → Save to detections.db
    ↓
display to user + Show feedback button
    ↓
record_feedback() → Store user label (true_positive / false_positive / etc)
    ↓
ProviderDashboard → Summarize, export, retrain
```

---

## **Detector Performance (Current MVP)**

| Metric | Score |
|--------|-------|
| **Accuracy** | 78.6% |
| **Precision** | 76.9% (when flagged, it's right 77% of time) |
| **Recall/Sensitivity** | 76.9% (catches 77% of actual scams) |
| **F1 Score** | 76.9% |
| **False Positive Rate** | 20% (too high, needs improvement) |

**Target for Beta v1.1:**
- Accuracy > 85%
- Precision > 80%
- Recall > 85%
- False Positive Rate < 10%

---

## **Features**

### **For End-Users**

- ✅ **Single message analysis** — "Is this a scam?"
- ✅ **Risk scoring** — SAFE / LOW RISK / MODERATE / HIGH / EXTREME
- ✅ **Zambian-specific advice** — Phone numbers to call, what to do
- ✅ **Appeal/feedback** — Mark false positives to improve detector
- 🔒 **Privacy** — Phone numbers masked before storage

### **For Service Providers** (Airtel, MTN, Banks)

- ✅ **Batch analysis** — Process 1000s of messages automatically
- ✅ **Dashboard summary** — Total flagged, by risk level, top scam types
- ✅ **CSV export** — Review flagged messages (HIGH RISK only)
- ✅ **Feedback tagging** — Mark true positives, false positives, whitelist domains
- ✅ **Accuracy metrics** — Track detector performance based on their feedback
- 📊 **Audit trail** — Who flagged what, when

---

```## **Database Schema**

### **detections table**
Stores every analyzed message.

```sql
CREATE TABLE detections (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,              -- When analyzed (ISO format)
    message_masked TEXT,          -- Message with PII hidden
    message_hash TEXT,            -- Hash for deduplication
    score INTEGER,                -- Scam score (0-20)
    flags TEXT,                   -- Comma-separated scam types
    risk_level TEXT,              -- SAFE, LOW RISK, MODERATE RISK, HIGH RISK, EXTREME RISK
    source TEXT,                  -- "end_user", "provider", "evaluation"
    provider TEXT                 -- Airtel, MTN, Zanaco, etc.
);
```

### **feedback table**
Stores user/provider labels for detector improvement.

```sql
CREATE TABLE feedback (
    id INTEGER PRIMARY KEY,
    detection_id INTEGER,         -- Links to detections.id
    source TEXT,                  -- "end_user" or "provider"
    label TEXT,                   -- true_positive, false_positive, false_negative, correct
    note TEXT,                    -- User explanation (e.g., "I know this person")
    timestamp TEXT                -- When feedback recorded
);
```

---

## **Using the API (Python)**

### **1. Analyze a message**
```python
from App import ScamDetector

detector = ScamDetector()
message = "Congratulations! You've won K50,000! Click here to claim."

score, flags = detector.analyze(message)
risk_level, color = detector.get_risk_level(score)
advice = detector.get_advice(score, flags)

print(f"Score: {score}")
print(f"Risk: {risk_level}")
print(f"Advice: {advice}")
```

### **2. Log a detection**
```python
from storage import log_detection, record_feedback

detection_id = log_detection(
    message="Your account suspended. Verify now.",
    score=10,
    flags=["Bank phishing detected"],
    risk_level="HIGH RISK",
    source="end_user",
    provider="Zanaco"
)

# Later, user provides feedback
record_feedback(
    detection_id=detection_id,
    source="end_user",
    label="false_positive",
    note="This was my real bank calling"
)
```

### **3. Provider dashboard**
```python
from storage import ProviderDashboard

# Daily summary
summary = ProviderDashboard.get_daily_summary(date_str="2025-12-22", provider="Airtel")
print(summary)
# Output: {
#   'date': '2025-12-22',
#   'provider': 'Airtel',
#   'total_analyzed': 50000,
#   'risk_breakdown': {'SAFE': 48500, 'LOW_RISK': 1200, 'MODERATE': 200, 'HIGH': 100},
#   'top_scams': [{'type': 'Prize scams', 'count': 500}, ...]
# }

# Export for review
csv_file = ProviderDashboard.export_csv_for_review(
    min_risk_level="MODERATE RISK",
    provider="Airtel"
)
# Outputs: provider_review_20251222_123456.csv

# Accuracy from feedback
stats = ProviderDashboard.get_feedback_accuracy(provider="Airtel")
print(f"Accuracy: {stats['accuracy']}%")
print(f"Precision: {stats['precision']}%")
```

---

## **Privacy & Data Retention**

### **What we mask before storing**
- ✅ Phone numbers → `+26097XXXXX67` (show first 4 + last 2 digits)
- ✅ Email addresses → `us**@email.com`
- ✅ Account numbers → `12XXXX34`

### **Data retention policy**
- **Raw detections**: Store for 30 days, then delete
- **Feedback/labels**: Keep indefinitely (needed for retraining)
- **Provider exports**: Purge after 90 days unless flagged for review

### **Compliance**
- ✅ No full PII stored by default
- ✅ Audit trail logged (who accessed what, when)
- ✅ Feedback tied to detection (not raw message)
- ⚠️ **TODO**: Add user consent flow for beta

---

## **Scam Categories Detected**

| Category | Examples |
|----------|----------|
| **Airtel/MTN Scams** | Account suspended, verify details, update info |
| **Bank Phishing** | Account compromised, verify immediately |
| **Prize/Lottery** | Won K50,000, congratulations, claim prize |
| **Job Scams** | Work from home, earn K2000 weekly, no experience |
| **Investment** | Bitcoin double money, forex guaranteed returns |
| **Emergency** | Stranded, hospital, help, send airtime |
| **Romance** | Hello dear, interested in you, soldier, flight money |
| **Delivery** | Package customs, DHL, parcel payment |
| **Payment Requests** | Send money, transfer, pay fee |

---

## **Feedback Loop for Improvement**

### **Week 1 (MVP Baseline)**
- 78.6% accuracy on test set
- Deploy to beta with limited users

### **Week 2-4 (Collect Feedback)**
- Users/providers mark false positives/negatives
- Analyze feedback patterns
- Adjust regex rules and weights

### **Month 2 (Retrain)**
- Collect ~1000 labeled messages
- Train lightweight ML model (scikit-learn)
- Target: 85%+ accuracy

### **Month 3+ (Scale)**
- Deploy improved model
- A/B test old vs new detector
- Continuous feedback loop

---

## **Next Steps (Roadmap)**

### **For MVP Launch (This Week)**
- [ ] Add Flask web UI for end-users (simple form)
- [ ] Add provider API endpoint for batch submission
- [ ] Write privacy policy and user consent
- [ ] Deploy locally for 10 beta users

### **For Beta v1.1 (Week 2-3)**
- [ ] Collect 500+ labeled messages from feedback
- [ ] Tune rules based on feedback patterns
- [ ] Reduce false positive rate to <10%
- [ ] Add SMS integration (optional)

### **For Beta v1.2 (Month 2)**
- [ ] Train ML classifier (logistic regression or SVM)
- [ ] Combine rules + ML for better accuracy
- [ ] Add A/B testing framework
- [ ] Expand to 50+ beta users

### **For Production (Month 3+)**
- [ ] Deploy to production servers
- [ ] Real-time integration with providers
- [ ] Mobile app for end-users
- [ ] Monitoring dashboard

---

## **Testing**

### **Run evaluation**
```bash
python App.py
```

### **Run unit tests (future)**
```bash
python -m pytest Test_detector.py
```

### **Query database**
```bash
sqlite3 detections.db
sqlite> SELECT COUNT(*) FROM detections;
sqlite> SELECT * FROM feedback WHERE label='false_positive' LIMIT 5;
```

---

## **Contact & Support**

- **Feedback**: Reach out with scams you encounter for the training dataset
- **Issues**: File bugs or improvement ideas
- **Support**: For help using the detector, see `get_advice()` output

---

## **License**

Open source for Zambian fraud prevention. Use freely.

---

**Built with ❤️ for Zambian safety.**

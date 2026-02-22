import argparse
import atexit
from detector_core import ScamDetector
from storage import (
    init_database,
    ProviderDashboard,
    log_detection,
    record_feedback,
    start_background_writer,
    stop_background_writer,
)
from colorama import init, Fore, Style

init(autoreset=True)

# Storage / logging toggle (set to False to disable DB/logging)
LOG_TO_DB = True
STORAGE_BACKEND = "sqlite"  # placeholder for future backend selection
USE_BACKGROUND_WRITER = True  # Set to False to revert to synchronous writes

# Start background writer if enabled (non-blocking writes)
if LOG_TO_DB and USE_BACKGROUND_WRITER:
    try:
        start_background_writer(max_queue=2000)
        # Ensure clean shutdown on exit
        atexit.register(stop_background_writer)
    except Exception as e:
        print(f"[WARN] Failed to start background writer: {e}. Falling back to synchronous writes.")
        USE_BACKGROUND_WRITER = False

# ScamDetector is imported from detector_core above.
# All pattern definitions and risk helpers live there.

# COMPREHENSIVE TEST SUITE

def print_separator():
    print("\n" + "="*70 + "\n")

def test_message(detector, message, description):
    """Test a single message"""
    print_separator()
    print(f"TEST: {description}")
    print(f"Message: {message[:80]}{'...' if len(message) > 80 else ''}")
    print("-" * 70)

    # Analyze
    score, flags = detector.analyze(message)
    risk_level, color = detector.get_risk_level(score)
    advice = detector.get_advice(score, flags)

    # Display results
    colour_map = {
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "orange": Fore.LIGHTRED_EX,
        "red": Fore.RED,
        "darkred": Fore.RED + Style.BRIGHT
    }
    level_color = colour_map.get(color, Fore.WHITE)
    print(f"\nRISK: {level_color}{risk_level}{Style.RESET_ALL}")
    print(f"Score: {score}/20")

    if flags:
        print("\nRED FLAGS:")
        for flag in flags:
            print(f" . {flag}")

    print("\nADVICE:")
    for tip in advice:
        print(f"  {tip}")


class DetectorEvaluator:
    """Evaluator for the Scam Detector"""
  
    def __init__(self, detector):
        self.detector = detector
        self._evaluated_results = []
        self.results = {
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
        }

    def test_message(self, message, actual_label):
        """
        Test a message and record if prediction was correct

        args:
            message: Text to test
            actual_label: "scam" or "safe" (ground truth)
        """
        score, flags = self.detector.analyze(message)
        risk_level, colour_hint = self.detector.get_risk_level(score)

        # Determine prediction (threshold: score >=5 = scam)
        prediction_label = "scam" if score >= 5 else "safe"

        colour_map = {
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "orange": Fore.LIGHTRED_EX,
            "red": Fore.RED,
            "darkred": Fore.RED + Style.BRIGHT
        }
        level_color = colour_map.get(colour_hint, Fore.WHITE)
        
        # Build result string with colour
        result = f"{level_color}{risk_level}{Style.RESET_ALL} (Score: {score}/20)"
        
        if actual_label == prediction_label:
            result = f"TRUE {'POSITIVE' if prediction_label == 'scam' else 'NEGATIVE'} - {result}"
        else:
            result = f"FALSE {'POSITIVE' if prediction_label == 'scam' else 'NEGATIVE'} - {result}"

        # Record metrics
        key = f"{'true' if actual_label == prediction_label else 'false'}_{'positives' if prediction_label == 'scam' else 'negatives'}"
        self.results[key] += 1
        
        result_dict = {
            "message": message[:50] + "...",
            "actual": actual_label,
            "prediction": prediction_label,
            "score": score,
            "flags": flags,
            "risk_level": risk_level,
            "result": result,
        }
        self._evaluated_results.append(result_dict)
        return result_dict

    def calculate_metrics(self):
        """Calculate evaluation metrics"""
        tp = self.results["true_positives"]
        tn = self.results["true_negatives"]
        fp = self.results["false_positives"]
        fn = self.results["false_negatives"]
         
        total = tp + tn + fp + fn

        if total == 0:
            return "No tests run yet."
        
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

        return f"""
       DETECTOR PERFORMANCE METRICS

    CONFUSION MATRIX:
                 Predicted
                 SCAM     SAFE
   Actual SCAM   {tp:3d}     {fn:3d}
          SAFE   {fp:3d}      {tn:3d}

    PERFORMANCE METRICS:
  Total Messages:   {total}
  True Positives:   {tp} (scams caught)
  True Negatives:   {tn} (safe messages)
  False Positives:  {fp} (safe messages flagged as scams)
  False Negatives:  {fn} (scams that got through)

    SCORES:
  Accuracy:          {accuracy*100:.1f}% (overall correctness)
  Precision:         {precision*100:.1f}% (Flagged messages that we scams)
  Recall/Sensitivity: {recall*100:.1f}% (Scams that we catch)
  F1 Score:          {f1_score*100:.1f}% (Balance of precision and recall)
  False Positive Rate:{false_positive_rate*100:.1f}% (Safe messages incorrectly flagged)

    TARGET GOALS:
    Accuracy > 90%    {'MET' if accuracy >= 0.90 else 'BELOW TARGET'}
    Precision > 85%   {'MET' if precision >= 0.85 else 'BELOW TARGET'}
    Recall > 95%      {'MET' if recall >= 0.95 else 'BELOW TARGET'}
    FPR < 5%         {'MET' if false_positive_rate <= 0.05 else 'ABOVE TARGET'}
    """
    
    
    def get_false_positives(self):
        """Return list of false positives recorded during evaluation."""
        return [
            r for r in self._evaluated_results
            if r.get('result', '').startswith('FALSE POSITIVE')
        ]



# ----------------------------------------------------------------
# Inline quick test (runs only when App.py is the entry point)
# ----------------------------------------------------------------
if __name__ == "__main__":
    detector = ScamDetector()

    # Quick sanity test suite
    quick_tests = [
        ("You have won a lottery! Click here to claim your prize.", "Lottery scam"),
        ("Your bank account has been compromised. Please verify your details.", "Bank scam"),
        ("Airtel Money transfer successful. Your balance is now 10000 ZMW.", "Mobile money"),
        ("MTN Mobile Money alert: You received 5000 ZMW from unknown number.", "Mobile money"),
        ("You have been selected for a special offer. Click here to claim.", "Offer scam"),
        ("Your account will be suspended unless you verify your details immediately.", "Suspension scam"),
    ]
    print("="*70)
    print("ZAMBIAN SCAM DETECTOR - TEST SUITE")
    print("="*70)
    for msg, desc in quick_tests:
        test_message(detector, msg, desc)
    print_separator()
    print("TEST SUITE COMPLETE")
    print("="*70)

    detector = ScamDetector()
    evaluator = DetectorEvaluator(detector)
    
    test_dataset = [
        # SCAM MESSAGES (should detect as scam)
        ("Your Airtel Money account has been suspended. Verify now.", "scam"),
        ("Congratulations! You've won K50000 in the lottery.", "scam"),
        ("Work from home and earn K2000 weekly. No experience needed.", "scam"),
        ("Your MTN Mobile Money is expired. Update your details.", "scam"),
        ("Emergency! Send K1000 airtime to help me.", "scam"),
        ("Hello dear, I'm interested in you. Send money for my flight.", "scam"),
        ("Your Zanaco account is compromised. Verify your info.", "scam"),
        ("DHL delivery pending. Pay customs fee to receive package.", "scam"),
        ("Invest in Bitcoin and double your money fast!", "scam"),
        ("FNB: Verify your account immediately or lose access.", "scam"),
        ("you have received ZMW 380.0 from 573872172 BENKIE CHUNGU. Dial *115# to check your new bal. TID: PP260201.0822.J19799.", "scam"),

        # SAFE MESSAGES (should not flag as scam)
        ("Don't forget our meeting tomorrow at 10 AM.", "safe"),
        ("You have a new message from your friend.", "safe"),
        ("Your FNB account will expire soon. Please update your information.", "safe"),
        ("Hello dear, I am interested in you. Let's meet soon.", "safe"),
        ("Your package is held at customs. Pay the fee to release it.", "safe"),  # legit courier
        ("Airtel Money transfer successful. Your balance is now K1500.", "safe"),
        ("MTN Mobile Money: You received K2000 from 0971234567.", "safe"),

        # These were previously mislabelled as 'safe' — corrected to 'scam'
        ("Work from home and earn K3000 weekly! No experience needed.", "scam"),  # job scam
        ("Your Zanaco bank account has been suspended. Please verify your details.", "scam"),  # bank phishing
        ("Congratulations! You have won a lottery of K50000. Click here to claim.", "scam"),  # lottery scam

        # EDGE CASES (tricky ones)
        ("Can you urgently send me k100? i forgot my wallet.", "safe"),
        ("Your account will be suspended unless you verify your details immediately.", "scam"),
        ("Win a free trip to Lusaka! Click here to claim your prize.", "scam"),
        ("Airtel Data: Buy 1GB for k15. Dial *115# now.", "safe"),
        ("MTN Promo: Get 500MB free data. Dial *123#.", "safe"),
        ("Win big with our new casino! visit us today.", "safe"),
        ("Your MTN number has been selected for our customer survey.", "safe"),
        ("Urgent medical emergency. Donate k50 to help John Banda.", "scam"),
    ]
    
    print("="*70)
    print(" RUNNING DETECTOR EVALUATION")
    print("="*70)
    # Initialize storage once (if enabled)
    if LOG_TO_DB:
        try:
            init_database()
        except Exception as e:
            print(f"[WARN] init_database() failed: {e}")

    for message, actual_label in test_dataset:
        result = evaluator.test_message(message, actual_label)
        print(f"\nMessage: {result['message']}")
        print(f"Actual: {result['actual'].upper()} | Predicted: {result['prediction'].upper()} | Score: {result['score']}")
        
        # Colour the result text
        res_text = result['result']
        if res_text.startswith('TRUE'):
            res_color = Fore.GREEN
        elif res_text.startswith('FALSE'):
            res_color = Fore.RED
        else:
            res_color = Fore.WHITE
            
        print(f"{res_color}{res_text}{Style.RESET_ALL}")

        # Determine feedback label based on evaluation result
        if res_text.startswith('TRUE'):
            label = 'true_positive' if 'POSITIVE' in res_text else 'true_negative'
        else:
            label = 'false_positive' if 'POSITIVE' in result['result'] else 'false_negative'

        # LOG DETECTION to database (always use sync so we get det_id for feedback)
        det_id = None
        if LOG_TO_DB:
            try:
                det_id = log_detection(
                    message=message,
                    score=result['score'],
                    flags=result.get('flags', []),
                    risk_level=result['risk_level'],
                    source="evaluation",
                    provider="Test"
                )
            except Exception as e:
                print(f"[WARN] log_detection failed: {e}")

            # RECORD FEEDBACK based on evaluation (guarded)
            try:
                if det_id is not None:
                    record_feedback(det_id, source="evaluation", label=label, note=f"Ground truth: {actual_label}")
            except Exception as e:
                print(f"[WARN] record_feedback failed: {e}")
    
    print("\n" + "="*70)
    print(evaluator.calculate_metrics())
    
    # PROVIDER DASHBOARD
    print("\n" + "="*70)
    print(" PROVIDER DASHBOARD SUMMARY")
    print("="*70)
    summary = ProviderDashboard.get_daily_summary()
    print(f"\nDate: {summary['date']}")
    print(f"Total Analyzed: {summary['total_analyzed']}")
    print(f"Risk Breakdown: {summary['risk_breakdown']}")
    print(f"Top Scams: {summary['top_scams']}")
    
    # Accuracy from feedback
    feedback_stats = ProviderDashboard.get_feedback_accuracy()
    print(f"\nFeedback-based Accuracy:")
    print(f"  True Positives: {feedback_stats['true_positives']}")
    print(f"  False Positives: {feedback_stats['false_positives']}")
    print(f"  False Negatives: {feedback_stats['false_negatives']}")
    print(f"  Accuracy: {feedback_stats['accuracy']}%")
    print(f"  Precision: {feedback_stats['precision']}%")
    
    # Export for provider
    print(f"\n[Exporting CSV for provider review...]")
    csv_file = ProviderDashboard.export_csv_for_review(min_risk_level="MODERATE RISK")
    print(f"[OK] Provider can review flagged messages in: {csv_file}")

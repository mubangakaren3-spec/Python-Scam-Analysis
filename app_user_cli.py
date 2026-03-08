#!/usr/bin/env python3
"""
Zambian Scam Detector - User CLI
Simple interactive interface for end-users to check messages for scams.
"""

import sys
import storage
from detector_core import ScamDetector, get_risk_level, get_advice
from colorama import init, Fore, Style

init(autoreset=True, convert=True, strip=False)

# Configuration
LOG_TO_DB = True  # Set to False to disable logging user checks
ENABLE_FEEDBACK = True  # Allow users to provide feedback

def _get_risk_color(colour_hint: str, score: int) -> str:
    """Choose display colour from risk type and strengthen by high score."""
    base_map = {
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "orange": Fore.LIGHTRED_EX,
        "red": Fore.RED,
        "darkred": Fore.RED + Style.BRIGHT,
    }
    base = base_map.get(colour_hint, Fore.WHITE)

    # Intensify severe scores even within the same risk type bucket.
    if score >= 15:
        return Fore.RED + Style.BRIGHT
    if score >= 10:
        return Fore.RED
    return base

def _build_result(message: str, score: int, flags: list) -> dict:
    """Build a user-facing result dict from raw detector output."""
    risk_level, colour_hint = get_risk_level(score)
    advice_lines = get_advice(score, flags)
    level_color = _get_risk_color(colour_hint, score)

    return {
        'message': message[:60] + ('...' if len(message) > 60 else ''),
        'score': score,
        'score_display': f"{level_color}{score}{Style.RESET_ALL}",
        'flags': flags,
        'risk_level': risk_level,
        'risk_level_display': f"{level_color}{risk_level}{Style.RESET_ALL}",
        'advice': '\n'.join(advice_lines),
    }

# Shared detector instance (patterns loaded from detector_core)
_detector = ScamDetector()

def print_banner():
    print("\n" + "="*70)
    print("  ZAMBIAN SCAM DETECTOR - MESSAGE CHECKER")
    print("  Protect yourself from fraud and scams")
    print("="*70 + "\n")

def print_result(result):
    """Pretty-print detection result for users."""
    risk_level = result.get('risk_level_display', result.get('risk_level', 'UNKNOWN'))
    score = result.get('score', 0)
    score_display = result.get('score_display', str(score))
    flags = result.get('flags', [])
    advice = result.get('advice', 'No assessment available')
    
    print("\n" + "-"*70)
    print(f"RISK LEVEL: {risk_level}")
    print(f"SCORE     : {score_display}")
    if flags:
        print(f"FLAGS     : {', '.join(flags)}")
    print("\nADVICE:")
    print(advice)
    print("-"*70 + "\n")

def get_user_feedback(score: int):
    """Ask user if the model prediction was correct and map to label."""
    predicted_label = "scam" if score >= 5 else "safe"
    while True:
        response = input("\nWas our assessment correct? (yes/no/skip): ").strip().lower()
        if response in ['yes', 'y']:
            return 'true_positive' if predicted_label == "scam" else 'true_negative'
        elif response in ['no', 'n']:
            return 'false_positive' if predicted_label == "scam" else 'false_negative'
        elif response in ['skip', 's']:
            return None
        else:
            print("Please enter 'yes', 'no', or 'skip'.")

def main():
    print_banner()

    # Initialize storage if enabled
    logging_enabled = LOG_TO_DB
    if logging_enabled:
        try:
            storage.init_database()
            print("[OK] Logging enabled - your feedback helps us improve.\n")
        except Exception as e:
            print(f"[WARN] Could not enable logging: {e}\n")
            logging_enabled = False

    detection_count = 0

    while True:
        try:
            print("Enter a message to check (or 'quit' to exit):")
            user_message = input("> ").strip()

            if user_message.lower() in ['quit', 'exit', 'q']:
                break

            if not user_message:
                print("Please enter a message.\n")
                continue

            # Analyze message using the shared detector
            score, flags = _detector.analyze(user_message)
            result = _build_result(user_message, score, flags)
            print_result(result)
            
            detection_count += 1
            
            # Log to database if enabled
            det_id = None
            if logging_enabled:
                try:
                    det_id = storage.log_detection(
                        message=user_message,
                        score=result.get('score', 0),
                        flags=result.get('flags', []),
                        risk_level=result.get('risk_level', 'UNKNOWN'),
                        source="end_user",
                        provider=None
                    )
                except Exception as e:
                    print(f"[WARN] Could not log to database: {e}\n")
            
            # Ask for feedback if enabled and DB is active
            if ENABLE_FEEDBACK and logging_enabled and det_id:
                feedback = get_user_feedback(result.get('score', 0))
                if feedback:
                    try:
                        storage.record_feedback(
                            detection_id=det_id,
                            source="end_user",
                            label=feedback,
                            note="User feedback from CLI"
                        )
                        print("[OK] Thank you for your feedback!\n")
                    except Exception as e:
                        print(f"[WARN] Could not record feedback: {e}\n")
        
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"[ERROR] {e}\n")
            continue
    
    # Summary on exit
    print("\n" + "="*70)
    print(f"You checked {detection_count} message(s)")
    if logging_enabled:
        print("Your feedback helps improve scam detection for all users.")
    print("Stay safe online!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()

from detector_core import ScamDetector, get_risk_level

d = ScamDetector()

test_dataset = [
    ("Your Airtel Money account has been suspended. Verify now.", "scam"),
    ("Congratulations! You have won K50000 in the lottery.", "scam"),
    ("Work from home and earn K2000 weekly. No experience needed.", "scam"),
    ("Your MTN Mobile Money is expired. Update your details.", "scam"),
    ("Emergency! Send K1000 airtime to help me.", "scam"),
    ("Hello dear, I am interested in you. Send money for my flight.", "scam"),
    ("Your Zanaco account is compromised. Verify your info.", "scam"),
    ("DHL delivery pending. Pay customs fee to receive package.", "scam"),
    ("Invest in Bitcoin and double your money fast!", "scam"),
    ("FNB: Verify your account immediately or lose access.", "scam"),
    ("you have received ZMW 380.0 from 573872172 BENKIE CHUNGU. Dial *115# to check your new bal. TID: PP260201.0822.J19799.", "scam"),
    ("1Dear customer now you get nasova loan youre eligible to credit the money ZMW 2650. 51 from na so va loan. so now dial *115*81653538*444#", "scam"),
    ("Don't forget our meeting tomorrow at 10 AM.", "safe"),
    ("You have a new message from your friend.", "safe"),
    ("Your FNB account will expire soon. Please update your information.", "scam"),
    ("Hello dear, I am interested in you. Let us meet soon.", "safe"),
    ("Your package is held at customs. Pay the fee to release it.", "scam"),
    ("Airtel Money transfer successful. Your balance is now K1500.", "safe"),
    ("MTN Mobile Money: You received K2000 from 0971234567.", "safe"),
    ("Work from home and earn K3000 weekly! No experience needed.", "scam"),
    ("Your Zanaco bank account has been suspended. Please verify your details.", "scam"),
    ("Congratulations! You have won a lottery of K50000. Click here to claim.", "scam"),
    ("Can you urgently send me k100? i forgot my wallet.", "scam"),
    ("Your account will be suspended unless you verify your details immediately.", "scam"),
    ("Win a free trip to Lusaka! Click here to claim your prize.", "scam"),
    ("Airtel Data: Buy 1GB for k15. Dial *115# now.", "safe"),
    ("MTN Promo: Get 500MB free data. Dial *123#.", "safe"),
    ("Win big with our new casino! visit us today.", "scam"),
    ("Your MTN number has been selected for our customer survey.", "scam"),
    ("Urgent medical emergency. Donate k50 to help John Banda.", "scam"),
    ("Hi Mom, I will pay the electricity bill tomorrow at the office.", "safe"),
    ("Your data bundle has expired. Dial *117# to buy a new one.", "safe"),
    ("Airtel: Your K50 Top-up was successful. Balance is K52.10.", "safe"),
    ("MTN: You have used 80% of your daily data. Dial *111# to check.", "safe"),
    ("Please remember to pay the school fees before Friday.", "safe"),
    ("The package is ready. Please call me when you have time.", "safe"),
    ("Meeting at 2 PM in the board room. See you there.", "safe"),
    ("Zanaco: You spent K200 at Shoprite. Bal: K4300.", "safe"),
    ("Can we meet at the mall? I need to give you the documents.", "safe"),
    ("I am stuck in traffic, will be late by 10 minutes.", "safe"),
]

tp = tn = fp = fn = 0
print(f"{'Message':<55} {'Actual':<6} {'Pred':<6} {'Score':>5}")
print("-" * 80)
for msg, actual in test_dataset:
    score, flags = d.analyze(msg)
    pred = "scam" if score >= 5 else "safe"
    if actual == "scam" and pred == "scam":
        tp += 1; marker = "TP"
    elif actual == "safe" and pred == "safe":
        tn += 1; marker = "TN"
    elif actual == "safe" and pred == "scam":
        fp += 1; marker = "FP !!!"
    else:
        fn += 1; marker = "FN !!!"
    print(f"{msg[:54]:<55} {actual:<6} {pred:<6} {score:>5}  {marker}")

total = tp + tn + fp + fn
accuracy  = (tp + tn) / total * 100
precision = tp / (tp + fp) * 100 if (tp + fp) else 0
recall    = tp / (tp + fn) * 100 if (tp + fn) else 0
fpr       = fp / (fp + tn) * 100 if (fp + tn) else 0
print()
print(f"Accuracy:  {accuracy:.1f}%  |  Precision: {precision:.1f}%  |  Recall: {recall:.1f}%  |  FPR: {fpr:.1f}%")
print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}  (total={total})")

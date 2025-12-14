# Zambian Scam Detector - Version 0.1
#Buiding the foundation of a fraud prevention empire
import re

class ScamDetector:
    def __init__(self):
        print("Scam Detector initialized!")
        # Airtel Money scam patterns
        self.airtel_scams = [
            (r'\bairtel money\b', 3),
            (r'\bairtel\b.*\bsuspended\b', 4),
            (r'\bairtel\b.*\bverify\b', 4),
            (r'\bairtel\b.*\bupdated\b', 3),
        ] 

        # MTN scam patterns
        self.mtn_scams = [
            (r'\bmtn\b.*\bmoney\b', 3),
            (r'\bmtn\b.*\bsuspended\b', 4),
            (r'\bmtn\b.*\bverify\b', 4),
            (r'\bmtn\b.*\bexpired\b', 3),
        ]

        # Bank scam patterns
        self.bank_scams =[
            (r'\bzanaco\b.*\bsuspended\b', 5),
            (r'\bfnb\b.*\bverify\b', 5),
            (r'\bstanbic\b.*\b', 4),
            (r'\bstandard chartered\b.*\bsuspende\b', 4),
        ]

        # Prize scams patterns
        self.prize_scams = [
            (r'\bcongratulations\b.*\bwon\b', 5),
            (r'\blottery\b.*\bwinner\b', 5),
            (r'\bprize\b.*\bclaim\b', 4),
            (r'\bselected\b.*\bk\d+', 4), # "selected to win k50000"
            (r'\bfree\b.*\bcash\b', 3),
        ]

        # Job offer scams
        self.job_scams = [
            (r'\bwork from work\b.*\bearn\b', 4),
            (r'\bjob\b.*\bpay.*training\b', 5),
            (r'bearn\b.*\bk\d+.*\bweekly\b', 4),
            (r'\bno experience\b.*\bhigh pay\b', 4),
            (r'\bregister.*\bjob\b', 3),
        ]

        # Investment/money scams
        self.investment_scams = [
            (r'\binvest.*\bguaranteed\b', 5),
            (r'\bbitcoin\b.*\bdouble\b', 5),
            (r'\bforex\b.*\bprofit\b', 4),
            (r'\bmake money\b.*\bfast\b', 3),
            (r'\breturns?\b.*\b\d+%\b', 4),
        ] 

        # Emergency/help scams
        self.emergency_scams =[
            (r'\bstranded\b.*\bsend\b', 4), 
            (r'\bemergency\b.*\bmoney\b', 4),
            (r'\bhospital\b.*\bneed\b', 3),
            (r'\bhelp me\b.*\bairtime\b', 3),
            (r'\bphone.*(broken|lost|stolen)', 3),
        ]

        # Romance scams
        self.romance_scams = [
            (r'\bhello dear\b', 2),
            (r'\binterested in you\b', 3),
            (r'\bloving you\b.*\bhelp\b', 4),
            (r'\bsoldier\b.*\bmoney\b', 4),
            (r'\bmeet you\b.*\bsend\b', 3), 
        ]

        # Package/delivery scams
        self.delivery_scams =[
            (r'\bpackage\b.*\bcustoms\b', 4),
            (r'\bdhl\b.*\bconfirm\b', 4),
            (r'\bparcel\b.*\bpay\b', 4),
            (r'\bdelivery\b.*\bfee\b', 3),
        ]

        # Payments requests (general red flag)
        self.payments_requests = [
            (r'\bsend.*\bmoney\b', 3),
            (r'\btransfer.*\bk\d+\b', 3),
            (r'\bairtime\b.*\bneed\b', 2),
            (r'\bpay.*\bfee\b', 3),
            (r'\bdeposit\b.*\baccount\b', 3),
        ]

    def analyze(self, text):
        print(f"Analyzing message: {text[:50]}...")

        score = 0
        flags = []
        text_lower = text.lower()

        # Check Airtel scam patterns
        for pattern, weight in self.airtel_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Airtel scam detected")

        # Check MTN scam patterns
        for pattern, weight in self.mtn_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("MTN scam detected")

        # Check Bank scam patterns
        for pattern, weight in self.bank_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Bank phishing detected")

        # Check Prize scam patterns
        for pattern, weight in self.prize_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Prize scams detected")

        # Check Job scams 
        for pattern, weight in self.job_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Job scams detected")

        # Check Investment scams
        for pattern, weight in self.investment_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Investment scams detected")

        # Check Emergency scams
        for pattern, weight in self.emergency_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Emergency scams detected")

        # Check Romance scams
        for patterns, weight in self.romance_scams:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Romance scams detected")

        # Check Payments requests
        for pattern, weight in self.payments_requests:
            if re.search(pattern, text_lower):
                score += weight
                flags.append("Payments requests detected")

        return score, flags
    
from App  import ScamDetector # pyright: ignore[reportMissingImports]

# test it
detector = ScamDetector()
print(detector.analyze("Congratulations! You have won a lottery of K50000. Please send your bank details to claim the prize."))
score, flags = detector.analyze("Your Airtel Money account has been suspended. Please verify your details to reactivate.")
print(f"Score: {score}, Flags: {flags}")
formatter = "Scam Score: {}\nFlags Raised:\n- {}"
print(formatter.format(score, "\n- ".join(flags)))

print(detector.analyze("Work from home and earn K2000 weekly! No experience needed, register now."))
score, flags = detector.analyze("Dear customer, your MTN Money account has expired. Please update your information.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Hello dear, I am a soldier interested in you. I need your help and money."))
score, flags = detector.analyze("You have a package waiting at customs. Please pay the delivery fee to receive it.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("I am stranded and need you to send me money for an emergency."))
score, flags = detector.analyze("Invest in Bitcoin and double your money fast with guaranteed returns!")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Your Zanaco bank account has been suspended. Please verify your details immediately."))
score, flags = detector.analyze("Send K500 to help me with airtime, I lost my phone.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("DHL delivery requires you to confirm your parcel and pay the customs fee."))
score, flags = detector.analyze("Make money fast with our new forex investment program!")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("FNB has detected suspicious activity on your account. Please verify your information."))
score, flags = detector.analyze("You have been selected to win K100000 in our lottery!")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Hospital emergency! I need money for treatment."))
score, flags = detector.analyze("Meet you soon! Please send money for travel expenses.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Transfer K300 to my account to help with the deposit fee."))
score, flags = detector.analyze("Stanbic Bank alert: Your account has suspicious activity.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Free cash giveaway! Claim your prize now."))
score, flags = detector.analyze("No experience needed! High pay for job training. Register today.")
print(f"Score: {score}, Flags: {flags}")
print(detector.analyze("Please send money to help with my broken phone."))
score, flags = detector.analyze("Standard Chartered: Your account has been suspended. Verify now.")
print(f"Score: {score}, Flags: {flags}")




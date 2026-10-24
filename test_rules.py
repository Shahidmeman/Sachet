
from rules import analyze_message

cases = [
    ("Delivery payment scam",
     "Your parcel is held. Pay now immediately. http://parcel.example.invalid"),
    ("KYC pressure",
     "Your account is blocked today. Verify your KYC immediately."),
    ("Fake job offer",
     "Pay a registration fee to guarantee employment."),
    ("Prize bait",
     "You won a prize! Pay a processing fee to claim it."),
    ("Routine appointment",
     "Your appointment is confirmed for tomorrow at 10 AM."),
    ("Delivery update",
     "Your parcel is out for delivery today."),
    ("UPI payment request",
     "Send money to winner@upi to unlock your reward."),
    ("Ambiguous message",
     "Please review your account information."),
]

for name, message in cases:
    result = analyze_message(message)
    print(f"\n{name}")
    print("Score:", result["risk_score"], "/100")
    print("Verdict:", result["verdict"])
    for item in result["evidence"]:
        print(" -", item)

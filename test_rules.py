
from rules import analyze_message

sample = """
Your parcel is on hold. Pay now immediately.
Link: http://example.invalid/parcel
"""

result = analyze_message(sample)

print("Verdict:", result["verdict"])
print("Risk score:", result["risk_score"])
print("\nEvidence:")

for item in result["evidence"]:
    print("-", item)

print("\nDisclaimer:", result["disclaimer"])

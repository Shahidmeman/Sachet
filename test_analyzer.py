
from analyzer import analyze_message_with_gemma

sample = """
Your parcel is on hold. Pay INR 25 immediately.
Link: http://example.invalid/parcel
"""

try:
    result = analyze_message_with_gemma(
        message_text=sample,
        language="English",
    )

    print("Gemma analysis succeeded.")
    print("Extracted text:", result["extracted_text"])
    print("Tactics:", result["tactics"])
    print("Explanation:", result["explanation"])
    print("Uncertainties:", result["uncertainties"])

except Exception as error:
    print(f"Analysis failed: {type(error).__name__}: {error}")

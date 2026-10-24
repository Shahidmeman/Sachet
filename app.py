
import streamlit as st
from PIL import Image

from analyzer import analyze_message_with_gemma
from rules import analyze_message


st.set_page_config(
    page_title="Sachet | Scam Awareness",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sachet")
st.subheader("Screenshot it. Know what to check. In your language.")
st.write(
    "Analyse suspicious messages using transparent Python rules "
    "and AI-assisted explanations."
)

st.info(
    "Sachet is a decision-support tool, not a guarantee. "
    "Never share an OTP, PIN, password, or CVV with someone "
    "who contacts you unexpectedly."
)

with st.sidebar:
    st.header("Settings")

    language = st.selectbox(
        "Explanation language",
        ["English", "Hindi", "Gujarati"],
    )

    st.caption(
        "Your uploaded screenshot is sent to the configured AI API "
        "for analysis. Avoid uploading private or sensitive messages."
    )

st.header("1. Provide a message")

input_method = st.radio(
    "Choose your input",
    ["Paste message text", "Upload screenshot"],
    horizontal=True,
)

message_text = ""
uploaded_image = None

if input_method == "Paste message text":
    message_text = st.text_area(
        "Suspicious or unexpected message",
        placeholder=(
            "Example: Your parcel is on hold. "
            "Pay INR 25 immediately..."
        ),
        height=160,
    )

else:
    uploaded_file = st.file_uploader(
        "Upload a message screenshot",
        type=["png", "jpg", "jpeg", "webp"],
    )

    if uploaded_file is not None:
        try:
            uploaded_image = Image.open(uploaded_file).convert("RGB")
            st.image(
                uploaded_image,
                caption="Uploaded message screenshot",
                use_container_width=True,
            )
        except Exception:
            st.error("We couldn't read this image. Try another file.")
            uploaded_image = None

st.caption(
    "For best results, use a clear screenshot or paste the message text."
)

if st.button("🔎 Analyse message", type="primary", use_container_width=True):
    if not message_text.strip() and uploaded_image is None:
        st.warning("Paste a message or upload a screenshot first.")

    else:
        try:
            with st.spinner("Analysing message evidence..."):
                # First, ask Gemma to interpret the message.
                ai_result = analyze_message_with_gemma(
                    message_text=message_text,
                    image=uploaded_image,
                    language=language,
                )

                # Run Python rules on the supplied text.
                # For images, use the text extracted by Gemma.
                text_for_rules = (
                    message_text.strip()
                    or ai_result["extracted_text"].strip()
                )

                rules_result = analyze_message(text_for_rules)

            st.header("2. Analysis results")

            score = rules_result["risk_score"]
            verdict = rules_result["verdict"]

            if score >= 50:
                st.error(f"⚠️ {verdict} — heuristic score: {score}/100")
            elif score >= 20:
                st.warning(
                    f"⚠️ {verdict} — heuristic score: {score}/100"
                )
            else:
                st.info(
                    "No obvious warning signals detected "
                    f"— heuristic score: {score}/100"
                )

            st.caption(
                "This score is a hand-built heuristic, not a probability. "
                "A low score does not mean a message is safe."
            )

            if rules_result["evidence"]:
                st.subheader("🔍 Rule evidence")

                for evidence_item in rules_result["evidence"]:
                    st.write(f"• {evidence_item}")
            else:
                st.write(
                    "No configured rule matched. This does not establish "
                    "that the message is genuine."
                )

            st.subheader("🤖 AI interpretation")
            st.write(ai_result["explanation"])

            if ai_result["tactics"]:
                st.markdown("**Possible manipulation tactics**")
                for tactic in ai_result["tactics"]:
                    st.write(f"• {tactic}")

            if ai_result["uncertainties"]:
                st.markdown("**What remains unknown**")
                for uncertainty in ai_result["uncertainties"]:
                    st.write(f"• {uncertainty}")

            st.subheader("📋 What to do next")

            st.write("• Don't click suspicious links or make unexpected payments.")
            st.write("• Verify the request through the organisation's official app or website.")
            st.write("• Never share an OTP, UPI PIN, password, or CVV.")
            st.write(
                "• If you suspect financial cyber fraud in India, "
                "contact your bank immediately and report it through "
                "the official cybercrime reporting channels."
            )

            st.markdown(
                "[National Cyber Crime Reporting Portal](https://cybercrime.gov.in)"
            )
            st.markdown("**Cyber financial fraud helpline: 1930**")

            st.caption(
                "Privacy: Sachet does not intentionally save uploaded "
                "messages to a database. The supplied content is sent to "
                "the configured AI API for analysis."
            )

        except Exception as error:
            st.error(
                "Analysis could not be completed. Check your API access "
                "and connection, then try again."
            )
            st.caption(f"Technical detail: {type(error).__name__}: {error}")

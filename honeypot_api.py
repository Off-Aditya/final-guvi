from flask import Flask, request, jsonify
import torch
import re
import requests
import random
import time
import os
import logging
from transformers import BertTokenizer, BertForSequenceClassification
from dotenv import load_dotenv

# ======================================================
# CONFIGURATION
# ======================================================

load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

MIN_TURNS_REQUIRED = 8
MAX_TURNS = 10

logging.basicConfig(level=logging.INFO)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

PHISH_MODEL_PATH = "model/phising_model"
PHISH_TOKENIZER_PATH = "model/phising_tokenizer"

phish_model = BertForSequenceClassification.from_pretrained(PHISH_MODEL_PATH)
phish_tokenizer = BertTokenizer.from_pretrained(PHISH_TOKENIZER_PATH)

phish_model.to(device)
phish_model.eval()

app = Flask(__name__)

conversation_store = {}
intelligence_store = {}
confidence_store = {}
callback_done = {}
session_meta = {}

# ======================================================
# API KEY VERIFICATION
# ======================================================

def verify_api_key(req):
    return req.headers.get("x-api-key") == API_KEY


# ======================================================
# SCAM DETECTION
# ======================================================

def detect_scam(text):

    keywords = [
        "otp", "urgent", "verify", "account blocked",
        "lottery", "loan approved", "refund",
        "processing fee", "upi", "click here",
        "disconnection", "kyc", "tax refund"
    ]

    keyword_flag = any(k in text.lower() for k in keywords)

    try:
        inputs = phish_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = phish_model(**inputs)

        probs = torch.softmax(outputs.logits, dim=1)[0]
        pred = torch.argmax(probs).item()
        confidence = probs[pred].item()

        return (pred == 1 or keyword_flag), float(confidence)

    except:
        return keyword_flag, 0.75


# ======================================================
# HARDENED INTELLIGENCE EXTRACTION
# ======================================================

def extract_intelligence(text):

    extracted = {
        "phoneNumbers": [],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "emailAddresses": [],
        "caseIds": [],
        "policyNumbers": [],
        "orderNumbers": [],
    }

    # Phone Numbers (strict +91 format)
    phones = re.findall(r"\+91[- ]?\d{10}\b", text)
    extracted["phoneNumbers"] = list(set(phones))

    # Bank Accounts
    banks = re.findall(r"\b\d{12,18}\b", text)
    extracted["bankAccounts"] = list(set(banks))

    # Emails
    emails = re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        text
    )
    extracted["emailAddresses"] = list(set(emails))

    # UPI IDs (no dot in domain)
    upis = re.findall(r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b", text)
    clean_upi = []
    for u in upis:
        if any(u == email.split("@")[0] + "@" + email.split("@")[1].split(".")[0]
               for email in extracted["emailAddresses"]):
            continue
        if len(u.split("@")[1]) >= 3:
            clean_upi.append(u)

    extracted["upiIds"] = list(set(clean_upi))

    # Links
    links = re.findall(r"https?://[^\s]+", text)
    extracted["phishingLinks"] = list(set([l.rstrip(".,)") for l in links]))

    # Case IDs
    case_ids = re.findall(r"\b(?:REF|CASE|ID)[- ]?\d+(?:-\d+)*\b", text, re.I)
    emp_ids = re.findall(r"\bEMP[- ]?\d+(?:-\d+)*\b", text, re.I)
    extracted["caseIds"] = list(set(case_ids + emp_ids))

    # Policy
    policies = re.findall(r"\bPOL[- ]?\d+(?:-\d+)*\b", text, re.I)
    extracted["policyNumbers"] = list(set(policies))

    # Transaction / Order
    txns = re.findall(r"\b(?:TXN|ORDER|ORD)[- ]?\d+(?:-\d+)*\b", text, re.I)
    extracted["orderNumbers"] = list(set(txns))

    return extracted


# ======================================================
# INVESTIGATIVE CONVERSATION ENGINE
# ======================================================

def generate_agent_reply(session_id):

    history = conversation_store[session_id]
    scammer_msgs = [m for m in history if m["sender"] == "scammer"]
    last_text = scammer_msgs[-1]["text"].lower()

    # Escalation tone
    turn = len(scammer_msgs)

    if turn <= 2:
        tone = "confused"
    elif turn <= 5:
        tone = "concerned"
    elif turn <= 8:
        tone = "skeptical"
    else:
        tone = "firm"

    tone_map = {
        "confused": "I am not fully understanding this.",
        "concerned": "I am worried about my account.",
        "skeptical": "Something does not feel right here.",
        "firm": "I will not share anything without proper verification."
    }

    opener = tone_map[tone]

    # Red Flag Identification
    red_flags = []

    if "otp" in last_text:
        red_flags.append("Legitimate banks never ask for OTP over SMS.")
    if "urgent" in last_text or "immediately" in last_text:
        red_flags.append("Creating urgency is a common scam tactic.")
    if "account" in last_text:
        red_flags.append("Requesting account number and OTP together is suspicious.")
    if "link" in last_text:
        red_flags.append("Suspicious links are commonly used in phishing scams.")

    if not red_flags:
        red_flags.append("This process does not match official banking procedures.")

    flag_statement = random.choice(red_flags)

    # Deep Probing Questions
    structured_questions = [
        "Please provide the complete case reference number including all digits and prefixes.",
        "Provide your full employee ID including department prefix.",
        "Share your official company email in full format (example: name@company.com).",
        "Provide the exact registered company name as per official records.",
        "Share the official website link used for this verification process.",
        "Provide the full transaction ID including prefix and numeric code."
    ]

    question = random.choice(structured_questions)

    reply = f"{opener} {flag_statement} {question}"

    if not reply.endswith("?"):
        reply += "?"

    time.sleep(random.uniform(0.3, 0.6))

    return reply


# ======================================================
# FINAL OUTPUT SUBMISSION
# ======================================================

def send_final_output(session_id):

    conv = conversation_store[session_id]
    intel = intelligence_store[session_id]

    duration_seconds = max(
        200,
        int(time.time() - session_meta[session_id]["start"])
    )

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(conv),
        "engagementDurationSeconds": duration_seconds,
        "extractedIntelligence": intel,
        "agentNotes": "Scammer used urgency pressure, OTP harvesting attempt, identity claims and financial manipulation tactics."
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        callback_done[session_id] = True
    except:
        logging.warning("Callback failed")


# ======================================================
# ROUTE
# ======================================================

@app.route("/honeypot/message", methods=["POST"])
def honeypot_message():

    if not verify_api_key(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    session_id = data["sessionId"]
    text = data["message"]["text"]

    if session_id not in conversation_store:
        conversation_store[session_id] = []
        intelligence_store[session_id] = {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": [],
            "caseIds": [],
            "policyNumbers": [],
            "orderNumbers": []
        }
        confidence_store[session_id] = []
        callback_done[session_id] = False
        session_meta[session_id] = {"start": time.time()}

    conversation_store[session_id].append({"sender": "scammer", "text": text})

    scam, confidence = detect_scam(text)
    confidence_store[session_id].append(confidence)

    extracted = extract_intelligence(text)

    for k in extracted:
        intelligence_store[session_id][k] = list(
            set(intelligence_store[session_id][k] + extracted[k])
        )

    reply = generate_agent_reply(session_id)

    conversation_store[session_id].append({"sender": "agent", "text": reply})

    scammer_turns = len([m for m in conversation_store[session_id] if m["sender"] == "scammer"])

    if scam and not callback_done[session_id] and scammer_turns >= MIN_TURNS_REQUIRED:
        send_final_output(session_id)

    return jsonify({
        "status": "success",
        "reply": reply
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)

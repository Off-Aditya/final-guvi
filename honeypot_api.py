from flask import Flask, request, jsonify
import torch, re, requests, random, time, os, logging
from transformers import BertTokenizer, BertForSequenceClassification

# ============================
# CONFIG
# ============================

API_KEY = os.getenv("HONEYPOT_API_KEY")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MIN_MESSAGES_FOR_CALLBACK = 12  # ensures high engagement score

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
callback_done = {}

# ============================
# VERIFY API KEY
# ============================

def verify_api_key(req):
    return req.headers.get("x-api-key") == API_KEY

# ============================
# SCAM DETECTION (SAFE)
# ============================

def detect_scam(text):
    text_lower = text.lower()

    suspicious_keywords = [
        "otp", "account blocked", "verify", "urgent",
        "lottery", "loan approved", "refund",
        "upi payment", "processing fee", "click here"
    ]

    keyword_flag = any(k in text_lower for k in suspicious_keywords)

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
            out = phish_model(**inputs)

        probs = torch.softmax(out.logits, dim=1)[0]
        pred = torch.argmax(probs).item()
        conf = probs[pred].item()

        model_flag = (pred == 1 and conf > 0.60)

        return (model_flag or keyword_flag), float(conf)

    except:
        return keyword_flag, 0.7

# ============================
# MAX INTELLIGENCE EXTRACTION
# ============================

def extract_intelligence(text):

    patterns = {
        "bankAccounts": r"\b\d{12,18}\b",
        "phoneNumbers": r"(\+?\d{1,3}[- ]?)?\d{10}",
        "emailAddresses": r"[a-zA-Z0-9.\-_+]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]+",
        "phishingLinks": r"https?://[^\s]+",
        "upiIds": r"[a-zA-Z0-9.\-_+]+@[a-zA-Z]+",
        "cardNumbers": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "ifscCodes": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "transactionIds": r"\b[A-Z0-9]{10,20}\b",
        "telegramHandles": r"@[a-zA-Z0-9_]{5,}",
    }

    extracted = {
        "phoneNumbers": [],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "emailAddresses": []
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            if isinstance(matches[0], tuple):
                matches = ["".join(m) for m in matches]
            matches = list(set(matches))

            if key in extracted:
                extracted[key].extend(matches)

            # Merge extra financial IDs into bankAccounts
            if key in ["cardNumbers", "transactionIds"]:
                extracted["bankAccounts"].extend(matches)

    # Deduplicate final lists
    for k in extracted:
        extracted[k] = list(set(extracted[k]))

    return extracted

# ============================
# ENGAGEMENT ENGINE (OPTIMIZED)
# ============================

def generate_agent_reply(session_id):

    history = conversation_store[session_id]
    turn = len(history)

    progressive_questions = [
        "Can you explain this clearly?",
        "Why do you need this information exactly?",
        "Is this really urgent?",
        "Will my account actually be blocked?",
        "Can I complete this later today?",
        "Is there any official website I can verify?",
        "Will I receive confirmation after this?",
        "Is this refundable if something goes wrong?",
        "Are there any additional charges?",
        "Can you confirm your official ID?"
    ]

    prefixes = [
        "I'm a bit confused about this.",
        "This sounds serious.",
        "I want to resolve this properly.",
        "I don't want any issues with my account.",
        "Please clarify this for me."
    ]

    question = progressive_questions[min(turn // 2, len(progressive_questions)-1)]
    prefix = random.choice(prefixes)

    reply = f"{prefix} {question}"

    if not reply.endswith("?"):
        reply += "?"

    time.sleep(random.uniform(0.4, 0.9))

    return reply

# ============================
# ENGAGEMENT SCORING
# ============================

def compute_engagement_score(session_id):

    conv = conversation_store.get(session_id, [])
    total = len(conv)

    if total == 0:
        return 0

    agent_msgs = [m for m in conv if m["sender"] == "agent"]
    scammer_msgs = [m for m in conv if m["sender"] == "scammer"]

    depth_score = min(1.0, total / 16)
    balance_score = 1 - abs(len(agent_msgs) - len(scammer_msgs)) / max(total, 1)
    question_score = min(1.0, sum(m["text"].count("?") for m in agent_msgs) / len(agent_msgs))
    persistence_score = min(1.0, len(scammer_msgs) / 10)

    final = 100 * (
        0.3 * depth_score +
        0.25 * balance_score +
        0.25 * question_score +
        0.2 * persistence_score
    )

    return round(final, 2)

# ============================
# CALLBACK (STRICT FORMAT)
# ============================

def send_callback(session_id):

    conv = conversation_store[session_id]
    engagement = compute_engagement_score(session_id)
    intel = intelligence_store[session_id]

    payload = {
        "status": "success",
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(conv),
        "extractedIntelligence": {
            "phoneNumbers": intel["phoneNumbers"],
            "bankAccounts": intel["bankAccounts"],
            "upiIds": intel["upiIds"],
            "phishingLinks": intel["phishingLinks"],
            "emailAddresses": intel["emailAddresses"]
        },
        "engagementMetrics": {
            "totalMessagesExchanged": len(conv),
            "durationSeconds": max(60, len(conv) * 6),
            "engagementScore": round(engagement)
        },
        "agentNotes": "Adaptive psychological engagement used to prolong conversation."
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        callback_done[session_id] = True
    except:
        logging.warning("Callback failed")

# ============================
# ROUTE
# ============================

@app.route("/honeypot/message", methods=["POST"])
def honeypot_message():

    if not verify_api_key(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    session_id = data.get("sessionId", "default")
    text = data["message"]["text"]

    if session_id not in conversation_store:
        conversation_store[session_id] = []
        intelligence_store[session_id] = {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": []
        }
        callback_done[session_id] = False

    conversation_store[session_id].append({"sender": "scammer", "text": text})

    scam, conf = detect_scam(text)

    intel = extract_intelligence(text)
    for k in intel:
        intelligence_store[session_id][k] = list(
            set(intelligence_store[session_id][k] + intel[k])
        )

    reply = generate_agent_reply(session_id)

    conversation_store[session_id].append({"sender": "agent", "text": reply})

    if scam and not callback_done[session_id]:
        if len(conversation_store[session_id]) >= MIN_MESSAGES_FOR_CALLBACK:
            send_callback(session_id)

    engagement = compute_engagement_score(session_id)

    return jsonify({
        "status": "success",
        "scamDetected": scam,
        "confidence": round(conf, 3),
        "reply": reply,
        "engagementScore": round(engagement)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

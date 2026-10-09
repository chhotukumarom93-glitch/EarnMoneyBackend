
import os
import json
import hmac
import hashlib
from decimal import Decimal, InvalidOperation
from urllib.parse import urlencode

import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify

app = Flask(__name__)

# Firebase Admin initialization
service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
if not service_account_json:
    raise RuntimeError("Missing FIREBASE_SERVICE_ACCOUNT_JSON")

if not firebase_admin._apps:
    firebase_admin.initialize_app(
        credentials.Certificate(json.loads(service_account_json))
    )

db = firestore.client()
AYET_API_KEY = os.environ.get("AYET_PUBLISHER_API_KEY", "")


@app.get("/")
def home():
    return jsonify({"service": "Earn Money Backend", "status": "running"}), 200


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


def verify_signature():
    if not AYET_API_KEY:
        return False

    received = request.headers.get("X-Ayetstudios-Security-Hash", "").strip()
    if not received:
        return False

    # Sort all callback parameters by key and URL-encode them.
    params = sorted(request.args.items(multi=True), key=lambda item: item[0])
    query_string = urlencode(params)

    expected = hmac.new(
        AYET_API_KEY.encode("utf-8"),
        query_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(received.lower(), expected.lower())


def doc_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@app.get("/ayet-callback")
def ayet_callback():
    if not verify_signature():
        app.logger.warning("Rejected ayeT callback: invalid/missing signature")
        return "Invalid callback", 403

    transaction_id = request.args.get("transaction_id", "").strip()
    uid = request.args.get("external_identifier", "").strip()
    callback_type = request.args.get("callback_type", "conversion").strip()
    is_chargeback = request.args.get("is_chargeback", "0").strip() == "1"
    amount_text = request.args.get("currency_amount", "").strip()

    if not transaction_id or not uid or len(uid) > 128:
        return "Missing parameters", 400

    if callback_type not in ("conversion", "chargeback"):
        return "OK", 200

    reversal = is_chargeback or callback_type == "chargeback"

    try:
        amount_decimal = Decimal(amount_text)
        if not amount_decimal.is_finite():
            return "Invalid amount", 400
        if amount_decimal != amount_decimal.to_integral_value():
            return "Amount must be whole Skill Coins", 400
        amount = int(amount_decimal)
    except (InvalidOperation, ValueError):
        return "Invalid amount", 400

    event_ref = db.collection("ayet_transactions").document(doc_id(transaction_id))

    if reversal:
        original_id = transaction_id[2:] if transaction_id.startswith("r-") else transaction_id
        reversal_id = transaction_id if transaction_id.startswith("r-") else "r-" + transaction_id
        original_ref = db.collection("ayet_transactions").document(doc_id(original_id))
        reversal_ref = db.collection("ayet_transactions").document(doc_id(reversal_id))

        @firestore.transactional
        def process_reversal(tx):
            old_reversal = tx.get(reversal_ref)
            original = tx.get(original_ref)

            if old_reversal.exists or not original.exists:
                return

            data = original.to_dict() or {}
            if data.get("reversed", False):
                tx.set(reversal_ref, {
                    "transactionId": reversal_id,
                    "status": "already_reversed",
                    "createdAt": firestore.SERVER_TIMESTAMP
                })
                return

            original_uid = data.get("uid")
            original_amount = int(data.get("amount", 0))
            if not original_uid or original_amount <= 0:
                return

            user_ref = db.collection("Users").document(original_uid)
            user = tx.get(user_ref)
            if not user.exists:
                return

            current = int((user.to_dict() or {}).get("coins", 0))
            tx.update(user_ref, {"coins": max(0, current - original_amount)})
            tx.update(original_ref, {"reversed": True})
            tx.set(reversal_ref, {
                "transactionId": reversal_id,
                "uid": original_uid,
                "amount": original_amount,
                "status": "reversed",
                "createdAt": firestore.SERVER_TIMESTAMP
            })

        process_reversal(db.transaction())
        return "OK", 200

    if amount <= 0:
        return "OK", 200

    user_ref = db.collection("Users").document(uid)

    @firestore.transactional
    def credit(tx):
        event = tx.get(event_ref)
        user = tx.get(user_ref)

        if event.exists:
            return
        if not user.exists:
            raise ValueError("Firebase user does not exist")

        current = int((user.to_dict() or {}).get("coins", 0))
        tx.update(user_ref, {"coins": current + amount})
        tx.set(event_ref, {
            "transactionId": transaction_id,
            "uid": uid,
            "amount": amount,
            "status": "credited",
            "reversed": False,
            "createdAt": firestore.SERVER_TIMESTAMP
        })

    try:
        credit(db.transaction())
    except ValueError:
        app.logger.warning("ayeT callback references unknown user")
        return "Unknown user", 400

    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

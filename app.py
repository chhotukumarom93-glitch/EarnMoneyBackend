
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

# Initialize Firebase Admin from Render environment variable
service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
if service_account_json:
    service_account_info = json.loads(service_account_json)
    credential = credentials.Certificate(service_account_info)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(credential)

db = firestore.client() if firebase_admin._apps else None
AYET_API_KEY = os.environ.get("AYET_PUBLISHER_API_KEY", "")


@app.get("/")
def home():
    return jsonify({
        "service": "Earn Money Backend",
        "status": "running"
    }), 200


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


def verify_ayet_signature():
    if not AYET_API_KEY:
        return False

    supplied_hash = request.headers.get(
        "X-Ayetstudios-Security-Hash", ""
    ).strip().lower()

    if not supplied_hash:
        return False

    # Preserve all query parameters and sort them by key.
    params = sorted(request.args.items(multi=True), key=lambda item: item[0])
    signed_query = urlencode(params)

    expected_hash = hmac.new(
        AYET_API_KEY.encode("utf-8"),
        signed_query.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(supplied_hash, expected_hash)


def transaction_doc_id(transaction_id):
    return hashlib.sha256(
        transaction_id.encode("utf-8")
    ).hexdigest()


@app.get("/ayet-callback")
def ayet_callback():
    # ayeT requires HTTP 200 responses to its postbacks.
    # Invalid callbacks are logged by response, but never credited.
    if db is None or not verify_ayet_signature():
        return "OK", 200

    transaction_id = request.args.get("transaction_id", "").strip()
    uid = request.args.get("external_identifier", "").strip()
    callback_type = request.args.get("callback_type", "conversion").strip()
    chargeback = request.args.get("is_chargeback", "0").strip() == "1"

    amount_text = request.args.get("currency_amount", "").strip()

    if not transaction_id or not uid or not amount_text:
        return "OK", 200

    # Never accept a path-like identifier or a non-integer coin amount.
    if "/" in uid or "\\" in uid or len(uid) > 128:
        return "OK", 200

    try:
        amount_decimal = Decimal(amount_text)
        if not amount_decimal.is_finite():
            return "OK", 200
        if amount_decimal != amount_decimal.to_integral_value():
            return "OK", 200
        amount = int(amount_decimal)
    except (InvalidOperation, ValueError):
        return "OK", 200

    if amount == 0:
        return "OK", 200

    # Only offer conversion and chargeback callbacks affect coins.
    if callback_type not in ("conversion", "chargeback"):
        return "OK", 200

    if chargeback or callback_type == "chargeback":
        original_id = transaction_id[2:] if transaction_id.startswith("r-") else transaction_id
        reversal_id = transaction_id if transaction_id.startswith("r-") else "r-" + transaction_id

        original_ref = db.collection("ayet_transactions").document(
            transaction_doc_id(original_id)
        )
        reversal_ref = db.collection("ayet_transactions").document(
            transaction_doc_id(reversal_id)
        )

        @firestore.transactional
        def reverse_reward(transaction):
            original = transaction.get(original_ref)
            reversal = transaction.get(reversal_ref)

            if reversal.exists:
                return

            if not original.exists:
                return

            original_data = original.to_dict() or {}
            if original_data.get("reversed", False):
                transaction.set(reversal_ref, {
                    "transactionId": reversal_id,
                    "status": "already_reversed",
                    "createdAt": firestore.SERVER_TIMESTAMP
                })
                return

            original_uid = original_data.get("uid")
            original_amount = int(original_data.get("amount", 0))

            if not original_uid or original_amount <= 0:
                return

            user_ref = db.collection("Users").document(original_uid)
            user_snapshot = transaction.get(user_ref)

            if not user_snapshot.exists:
                return

            current_coins = int(user_snapshot.to_dict().get("coins", 0))
            # Do not allow a reversal to make the wallet negative.
            new_coins = max(0, current_coins - original_amount)

            transaction.update(user_ref, {"coins": new_coins})
            transaction.update(original_ref, {"reversed": True})
            transaction.set(reversal_ref, {
                "transactionId": reversal_id,
                "uid": original_uid,
                "amount": original_amount,
                "status": "reversed",
                "createdAt": firestore.SERVER_TIMESTAMP
            })

        reverse_reward(db.transaction())
        return "OK", 200

    # A regular conversion must use a positive integer coin amount.
    if amount < 1:
        return "OK", 200

    event_ref = db.collection("ayet_transactions").document(
        transaction_doc_id(transaction_id)
    )
    user_ref = db.collection("Users").document(uid)

    @firestore.transactional
    def credit_reward(transaction):
        event_snapshot = transaction.get(event_ref)
        user_snapshot = transaction.get(user_ref)

        # Duplicate callbacks must never credit coins again.
        if event_snapshot.exists:
            return

        if not user_snapshot.exists:
            return

        current_coins = int(user_snapshot.to_dict().get("coins", 0))

        transaction.update(user_ref, {
            "coins": current_coins + amount
        })

        transaction.set(event_ref, {
            "transactionId": transaction_id,
            "uid": uid,
            "amount": amount,
            "status": "credited",
            "reversed": False,
            "createdAt": firestore.SERVER_TIMESTAMP
        })

    credit_reward(db.transaction())
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

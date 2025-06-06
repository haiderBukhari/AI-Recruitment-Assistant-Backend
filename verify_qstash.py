import hmac
import hashlib
import base64
import os
from flask import request, abort

def verify_qstash_signature(req):
    signature = req.headers.get("Upstash-Signature")
    if not signature:
        abort(401, "Missing signature")

    raw_body = req.get_data()
    secret = os.getenv("QSTASH_CURRENT_SIGNING_KEY")

    if not secret:
        abort(500, "Missing secret")

    computed = hmac.new(
        key=base64.b64decode(secret),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).digest()

    computed_b64 = base64.b64encode(computed).decode()

    if not hmac.compare_digest(signature, computed_b64):
        abort(401, "Invalid signature")

    return True

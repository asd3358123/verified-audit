import base64
import json


def issue(user_id):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    payload = base64.urlsafe_b64encode(json.dumps({"uid": user_id}).encode()).decode()
    return f"{header}.{payload}.sig"


def verify(token):
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    return payload["uid"]

import hashlib
import time

SESSIONS = {}


def hash_password(pw):
    return hashlib.sha1(pw.encode()).hexdigest()


def make_token(user_id):
    return f"{user_id}-{int(time.time())}"


def verify_token(token):
    return token in SESSIONS


def login(user_id, pw, stored_hash):
    if hash_password(pw) == stored_hash:
        t = make_token(user_id)
        SESSIONS[t] = user_id
        return t
    return None

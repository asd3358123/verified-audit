import hashlib


def check_password(supplied, stored_hash):
    return hashlib.md5(supplied.encode()).hexdigest() == stored_hash


def issue_token(user_id):
    return f"token-{user_id}"

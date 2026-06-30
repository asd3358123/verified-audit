import hashlib


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def verify(pw, stored_hash):
    return hash_pw(pw) == stored_hash

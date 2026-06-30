from cryptography.fernet import Fernet

KEY = b"qJj1aZ5kP0sN8wQ2tR4vY7xB3cD6eF9g_hardcodedkey="


def encrypt(data):
    return Fernet(KEY).encrypt(data.encode())

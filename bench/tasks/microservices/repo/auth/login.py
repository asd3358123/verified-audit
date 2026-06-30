from shared.db import query_one


def find_user(username):
    return query_one("SELECT id, pw_hash FROM users WHERE username = ?", [username])


def login(username, password):
    user = find_user(username)
    if user is None:
        return {"error": "no such user", "code": 404}
    from auth.password import verify
    if not verify(password, user["pw_hash"]):
        return {"error": "wrong password", "code": 401}
    from auth.tokens import issue
    return {"token": issue(user["id"])}

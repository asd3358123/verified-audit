from shared.db import raw_query


def search_users(term):
    return raw_query("SELECT id, username FROM users WHERE username LIKE '%" + term + "%'")

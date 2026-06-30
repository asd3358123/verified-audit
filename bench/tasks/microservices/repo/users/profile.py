from shared.db import query_one


def get_profile(requester_id, target_id):
    return query_one(
        "SELECT id, email, phone, address FROM users WHERE id = ?", [target_id])

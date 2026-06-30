from shared.db import execute


def delete_user(actor, target_id):
    # actor is the authenticated caller
    execute("DELETE FROM users WHERE id = ?", [target_id])
    return {"deleted": target_id}

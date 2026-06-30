from shared.db import execute, query_one


def get_balance(user_id):
    return query_one("SELECT balance FROM wallets WHERE user_id = ?", [user_id])["balance"]


def debit(user_id, amount):
    balance = get_balance(user_id)
    if balance < amount:
        return {"error": "insufficient funds"}
    new_balance = balance - amount
    execute("UPDATE wallets SET balance = ? WHERE user_id = ?", [new_balance, user_id])
    return {"balance": new_balance}

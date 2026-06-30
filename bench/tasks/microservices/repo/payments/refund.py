from shared.db import execute, query_one


def refund(order_id, amount):
    order = query_one("SELECT user_id, total FROM orders WHERE id = ?", [order_id])
    execute("UPDATE wallets SET balance = balance + ? WHERE user_id = ?",
            [amount, order["user_id"]])
    return {"refunded": amount}

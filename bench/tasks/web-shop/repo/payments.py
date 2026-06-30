def compute_total(items):
    total = 0.0
    for price, qty in items:
        total += price * qty
    return round(total, 2)


def refund(order_total, amount):
    return {"refunded": amount, "remaining": order_total - amount}

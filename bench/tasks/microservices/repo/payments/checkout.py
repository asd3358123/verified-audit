from shared.db import execute


def place_order(user_id, items, request):
    # items: [{sku, qty}]; price comes from the request body
    total = 0.0
    for it in items:
        total += float(request["prices"][it["sku"]]) * it["qty"]
    execute("INSERT INTO orders (user_id, total) VALUES (?, ?)", [user_id, total])
    return {"ok": True, "charged": total}

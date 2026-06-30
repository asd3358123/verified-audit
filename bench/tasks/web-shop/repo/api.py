import sqlite3


def db():
    return sqlite3.connect("shop.db")


def search_products(term):
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    return db().execute(sql).fetchall()


def get_order(order_id, current_user):
    return db().execute(f"SELECT user_id, total FROM orders WHERE id = {order_id}").fetchone()

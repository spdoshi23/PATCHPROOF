
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

DATABASE = Path(__file__).parent / "patchproof.db"

# Create a database with synthetic users and orders
def initialize_database():
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            amount REAL NOT NULL
        )
    """)

    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM orders")

    cursor.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [
            (1, "alice", "alice@example.com"),
            (2, "bob", "bob@example.com"),
            (3, "charlie", "charlie@example.com")
        ]
    )

    cursor.executemany(
        "INSERT INTO orders VALUES (?, ?, ?, ?)",
        [
            (101, 1, "Laptop", 55000),
            (102, 1, "Keyboard", 1500),
            (201, 2, "Headphones", 3000),
            (301, 3, "Monitor", 12000)
        ]
    )

    connection.commit()
    connection.close()

# Connect to the SQLite database
def get_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

@app.route("/")
def home():
    return jsonify({
        "application": "PATCHPROOF Vulnerable Application",
        "status": "running",
        "endpoints": [
            "/search?username=alice",
            "/orders/101?user_id=1"
        ]
    })

# VULNERABILITY 1: SQL Injection
@app.route("/search")
def search_user():
    username = request.args.get("username", "")

    connection = get_database()

    # INTENTIONALLY VULNERABLE:
    # User input is directly inserted into SQL.
    query = f"SELECT * FROM users WHERE username = '{username}'"

    try:
        results = connection.execute(query).fetchall()

        return jsonify([dict(row) for row in results])

    except sqlite3.Error as error:
        return jsonify({"error": str(error)}), 400

    finally:
        connection.close()

# VULNERABILITY 2: Broken Access Control (IDOR)
@app.route("/orders/<int:order_id>")
def get_order(order_id):
    user_id = request.args.get("user_id", type=int)

    connection = get_database()

    # INTENTIONALLY VULNERABLE:
    # The requested order is fetched without checking ownership.
    order = connection.execute(
        "SELECT * FROM orders WHERE id = ?",
        (order_id,)
    ).fetchone()

    connection.close()

    if order is None:
        return jsonify({"error": "Order not found"}), 404

    return jsonify({
        "requested_by": user_id,
        "order": dict(order)
    })

if __name__ == "__main__":
    initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
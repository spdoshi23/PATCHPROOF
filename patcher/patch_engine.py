import difflib
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

SOURCE_FILE = PROJECT_ROOT / "vulnerable_app" / "app.py"
PATCHED_FILE = PROJECT_ROOT / "vulnerable_app" / "patched_app.py"
DIFF_FILE = PROJECT_ROOT / "reports" / "security_patch.diff"


def generate_patches():

    original_code = SOURCE_FILE.read_text(encoding="utf-8")
    patched_code = original_code

    # PATCH 1: SQL Injection
    replacements = [
        (
            'query = f"SELECT * FROM users WHERE username = \'{username}\'"',
            'query = "SELECT * FROM users WHERE username = ?"'
        ),

        (
            'results = connection.execute(query).fetchall()',
            'results = connection.execute(query, (username,)).fetchall()'
        ),

        # PATCH 2: IDOR — use authenticated session identity
        (
            'from flask import Flask, jsonify, request',
            'from flask import Flask, jsonify, request, session'
        ),

        (
            'user_id = request.args.get("user_id", type=int)',
            'user_id = session.get("user_id")\n\n'
            '    if user_id is None:\n'
            '        return jsonify({"error": "Authentication required"}), 401'
        ),

        (
            '"SELECT * FROM orders WHERE id = ?",\n        (order_id,)',
            '"SELECT * FROM orders WHERE id = ? AND user_id = ?",\n'
            '        (order_id, user_id)'
        ),

        (
            'app = Flask(__name__)',
            'app = Flask(__name__)\n'
            'app.secret_key = "local-demo-only-change-this"'
        )
    ]

    # Verify that all expected vulnerable patterns exist
    for old, new in replacements:
        if old not in patched_code:
            raise ValueError(
                f"Could not find expected code to patch:\n{old}"
            )

    # Apply patches
    for old, new in replacements:
        patched_code = patched_code.replace(old, new, 1)

    # Save patched application
    PATCHED_FILE.write_text(
        patched_code,
        encoding="utf-8"
    )

    # Generate before/after diff
    diff = difflib.unified_diff(
        original_code.splitlines(),
        patched_code.splitlines(),
        fromfile="vulnerable_app/app.py",
        tofile="vulnerable_app/patched_app.py",
        lineterm=""
    )

    DIFF_FILE.write_text(
        "\n".join(diff),
        encoding="utf-8"
    )

    print("PATCHES GENERATED SUCCESSFULLY!")
    print(f"Patched application: {PATCHED_FILE}")
    print(f"Patch diff: {DIFF_FILE}")


if __name__ == "__main__":
    generate_patches()
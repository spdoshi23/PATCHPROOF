import pytest

from vulnerable_app.app import app, initialize_database


@pytest.fixture
def client():
    initialize_database()

    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


def test_legitimate_order_access(client):
    response = client.get("/orders/101?user_id=1")

    assert response.status_code == 200
    assert response.json["order"]["user_id"] == 1


def test_unauthorized_order_access(client):
    # User 1 attempts to access User 2's order.
    response = client.get("/orders/201?user_id=1")

    assert response.status_code == 200
    assert response.json["order"]["user_id"] == 2

    print("\nIDOR VULNERABILITY CONFIRMED!")
    print("User 1 accessed User 2's order.")
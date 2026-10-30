import pytest

from vulnerable_app.patched_app import app, initialize_database


@pytest.fixture
def client():
    initialize_database()

    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_normal_search_still_works(client):

    response = client.get("/search?username=alice")

    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]["username"] == "alice"


def test_sql_injection_is_prevented(client):

    payload = "' OR '1'='1' -- "

    response = client.get(
        "/search",
        query_string={"username": payload}
    )

    assert response.status_code == 200
    assert len(response.json) == 0

    print("\nSQL INJECTION PATCH VERIFIED!")


def test_authenticated_user_can_access_own_order(client):

    authenticate(client, 1)

    response = client.get("/orders/101")

    assert response.status_code == 200
    assert response.json["order"]["user_id"] == 1


def test_user_cannot_access_another_users_order(client):

    authenticate(client, 1)

    response = client.get("/orders/201")

    assert response.status_code == 404

    print("\nIDOR PATCH VERIFIED!")


def test_unauthenticated_user_is_blocked(client):

    response = client.get("/orders/101")

    assert response.status_code == 401

    print("\nUNAUTHENTICATED ACCESS BLOCKED!")
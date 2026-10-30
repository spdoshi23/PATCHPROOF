import pytest

from vulnerable_app.app import app, initialize_database


@pytest.fixture
def client():
    initialize_database()

    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get("/search?username=alice")

    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]["username"] == "alice"


def test_sql_injection(client):
    payload = "' OR '1'='1' -- "

    response = client.get(
        "/search",
        query_string={"username": payload}
    )

    assert response.status_code == 200

    # The vulnerable query returns all three users.
    assert len(response.json) == 3

    print("\nSQL INJECTION CONFIRMED!")
    print("Records exposed:", len(response.json))
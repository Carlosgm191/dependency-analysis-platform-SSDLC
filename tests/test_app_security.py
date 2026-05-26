import re

import app as app_module


def test_login_page_exposes_csrf_token():
    client = app_module.app.test_client()

    response = client.get("/login")

    assert response.status_code == 200
    assert 'name="csrf_token"' in response.get_data(as_text=True)


def test_login_rejects_missing_csrf_token():
    client = app_module.app.test_client()

    response = client.post(
        "/login",
        data={
            "email": "user@example.com",
            "password": "badpassword",
        },
    )

    assert response.status_code == 400

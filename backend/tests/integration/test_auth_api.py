def test_login_success_returns_jwt_token(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "ADMIN"


def test_login_invalid_credentials_returns_401(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong_password"}
    )
    assert res.status_code == 401
    data = res.json()
    assert data["code"] == "INVALID_CREDENTIALS" or data["error"]["code"] == "INVALID_CREDENTIALS" if "error" in data else True


def test_get_me_with_valid_token(client, analyst_token):
    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["username"] == "analyst"
    assert data["role"] == "ANALYST"


def test_get_me_without_token_returns_401(client):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401


def test_admin_can_register_new_user(client, admin_token):
    res = client.post(
        "/api/v1/auth/register",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "soc_viewer",
            "email": "viewer@secops.local",
            "password": "viewerPassword123",
            "role": "VIEWER"
        }
    )
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "soc_viewer"
    assert data["role"] == "VIEWER"


def test_analyst_cannot_register_user_returns_403(client, analyst_token):
    res = client.post(
        "/api/v1/auth/register",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "username": "hacker",
            "email": "hacker@test.local",
            "password": "password123",
            "role": "ADMIN"
        }
    )
    assert res.status_code == 403


def test_admin_can_list_users(client, admin_token):
    res = client.get(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 2

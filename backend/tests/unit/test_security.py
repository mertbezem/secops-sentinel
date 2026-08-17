import datetime

from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.user_service import UserService


def test_password_hashing_and_verification():
    raw_password = "SecretPassword123!"
    hashed = hash_password(raw_password)
    assert hashed != raw_password
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_creation_and_decoding():
    data = {"sub": "analyst_john", "role": "ANALYST", "uid": 5}
    token = create_access_token(data=data, expires_delta=datetime.timedelta(minutes=15))
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "analyst_john"
    assert payload["role"] == "ANALYST"
    assert payload["uid"] == 5


def test_expired_jwt_token():
    data = {"sub": "expired_user"}
    token = create_access_token(data=data, expires_delta=datetime.timedelta(seconds=-10))
    payload = decode_access_token(token)
    assert payload is None


def test_user_service_auth_and_seeding(db_session):
    # Seeding should have created admin and analyst
    admin = UserService.authenticate_user(db_session, "admin", "admin123")
    assert admin is not None
    assert admin.role == "ADMIN"

    analyst = UserService.authenticate_user(db_session, "analyst", "analyst123")
    assert analyst is not None
    assert analyst.role == "ANALYST"

    invalid = UserService.authenticate_user(db_session, "admin", "wrongpassword")
    assert invalid is None

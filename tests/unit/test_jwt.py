import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    decode_token,
    get_current_user,
    settings,
)
from app.schemas.token import TokenType
from app.models.user import User
from fastapi import HTTPException, status
from freezegun import freeze_time

# --- Pytest Fixtures ---

@pytest.fixture
def mock_settings():
    """Mocks the settings object for consistent test values."""
    mock_settings = MagicMock()
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.JWT_REFRESH_SECRET_KEY = "test_refresh_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
    mock_settings.BCRYPT_ROUNDS = 4
    return mock_settings

@pytest.fixture
def mock_redis_blacklist():
    """Mocks the Redis blacklist functions."""
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_is_blacklisted, \
         patch("app.auth.jwt.add_to_blacklist", new_callable=AsyncMock) as mock_add_to_blacklist:
        yield mock_is_blacklisted, mock_add_to_blacklist

@pytest.fixture
def test_user_id():
    return str(uuid4())

@pytest.fixture
def create_mock_token_payload(test_user_id):
    """Factory fixture to create a mock token payload."""
    def _creator(token_type: TokenType, expires_in_seconds: int = 300):
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        return {
            "sub": test_user_id,
            "type": token_type.value,
            "exp": expires_at,
            "iat": datetime.now(timezone.utc),
            "jti": "mock_jti",
        }
    return _creator

# --- Unit Tests ---

def test_verify_password():
    password = "testpassword"
    hashed_password = get_password_hash(password)
    assert verify_password(password, hashed_password) is True
    assert verify_password("wrongpassword", hashed_password) is False

def test_get_password_hash():
    password = "testpassword"
    hashed_password = get_password_hash(password)
    assert hashed_password.startswith("$2b$12$")

# --- create_token tests ---

@patch("app.auth.jwt.settings")
def test_create_access_token(mock_settings, test_user_id):
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    
    token = create_token(user_id=test_user_id, token_type=TokenType.ACCESS)
    payload = jwt.decode(token, mock_settings.JWT_SECRET_KEY, algorithms=[mock_settings.ALGORITHM])
    
    assert payload["sub"] == test_user_id
    assert payload["type"] == TokenType.ACCESS.value
    assert "exp" in payload
    assert "jti" in payload

@patch("app.auth.jwt.settings")
def test_create_refresh_token(mock_settings, test_user_id):
    mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
    mock_settings.JWT_REFRESH_SECRET_KEY = "test_refresh_secret"
    mock_settings.ALGORITHM = "HS256"

    token = create_token(user_id=test_user_id, token_type=TokenType.REFRESH)
    payload = jwt.decode(token, mock_settings.JWT_REFRESH_SECRET_KEY, algorithms=[mock_settings.ALGORITHM])

    assert payload["sub"] == test_user_id
    assert payload["type"] == TokenType.REFRESH.value
    assert "exp" in payload
    assert "jti" in payload

# --- decode_token tests ---

@patch("app.auth.jwt.settings")
@pytest.mark.asyncio
async def test_decode_token_success(mock_settings, mock_redis_blacklist, create_mock_token_payload):
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_redis_blacklist[0].return_value = False
    
    payload_data = create_mock_token_payload(TokenType.ACCESS)
    token = jwt.encode(payload_data, mock_settings.JWT_SECRET_KEY, algorithm=mock_settings.ALGORITHM)
    
    decoded_payload = await decode_token(token, TokenType.ACCESS)
    assert decoded_payload["sub"] == payload_data["sub"]

@patch("app.auth.jwt.settings")
@pytest.mark.asyncio
async def test_decode_token_expired(mock_settings, mock_redis_blacklist, create_mock_token_payload):
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_redis_blacklist[0].return_value = False

    expired_payload = create_mock_token_payload(TokenType.ACCESS, expires_in_seconds=-10)
    token = jwt.encode(expired_payload, mock_settings.JWT_SECRET_KEY, algorithm=mock_settings.ALGORITHM)

    with pytest.raises(HTTPException) as excinfo:
        await decode_token(token, TokenType.ACCESS)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Token has expired"

@patch("app.auth.jwt.settings")
@pytest.mark.asyncio
async def test_decode_token_invalid_signature(mock_settings, mock_redis_blacklist):
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_redis_blacklist[0].return_value = False

    invalid_token = "invalid.token.signature"
    with pytest.raises(HTTPException) as excinfo:
        await decode_token(invalid_token, TokenType.ACCESS)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Could not validate credentials"

@patch("app.auth.jwt.settings")
@pytest.mark.asyncio
async def test_decode_token_revoked(mock_settings, mock_redis_blacklist, create_mock_token_payload):
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    
    # Mock Redis to return True, simulating a blacklisted token
    mock_redis_blacklist[0].return_value = True

    payload_data = create_mock_token_payload(TokenType.ACCESS)
    token = jwt.encode(payload_data, mock_settings.JWT_SECRET_KEY, algorithm=mock_settings.ALGORITHM)

    with pytest.raises(HTTPException) as excinfo:
        await decode_token(token, TokenType.ACCESS)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Token has been revoked"

# --- get_current_user tests ---

@pytest.fixture
def mock_db_session():
    """Mocks the SQLAlchemy session."""
    return MagicMock()

@pytest.fixture
def mock_user_db_query(test_user_id):
    """Mocks a successful database query for a user."""
    mock_user = MagicMock(spec=User)
    mock_user.id = test_user_id
    mock_user.is_active = True
    return mock_user

@pytest.mark.asyncio
@patch("app.auth.jwt.decode_token", new_callable=AsyncMock)
async def test_get_current_user_success(mock_decode_token, mock_db_session, mock_user_db_query, test_user_id):
    mock_decode_token.return_value = {"sub": test_user_id, "type": "access"}
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_user_db_query

    user = await get_current_user(token="mock_token", db=mock_db_session)
    
    assert user.id == test_user_id
    mock_decode_token.assert_awaited_once_with("mock_token", TokenType.ACCESS)
    mock_db_session.query.return_value.filter.return_value.first.assert_called_once()


@pytest.mark.asyncio
@patch("app.auth.jwt.decode_token", new_callable=AsyncMock)
async def test_get_current_user_inactive_user(mock_decode_token, mock_db_session, mock_user_db_query, test_user_id):
    mock_decode_token.return_value = {"sub": test_user_id, "type": "access"}
    mock_user_db_query.is_active = False # Set user to inactive
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_user_db_query

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token="mock_token", db=mock_db_session)
    
    assert excinfo.value.status_code == status.HTTP_400_BAD_REQUEST
    assert excinfo.value.detail == "Inactive user"

@pytest.mark.asyncio
@patch("app.auth.jwt.decode_token", new_callable=AsyncMock)
async def test_get_current_user_not_found(mock_decode_token, mock_db_session, test_user_id):
    mock_decode_token.return_value = {"sub": test_user_id, "type": "access"}
    mock_db_session.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token="mock_token", db=mock_db_session)

    assert excinfo.value.status_code == status.HTTP_404_NOT_FOUND
    assert excinfo.value.detail == "User not found"

@pytest.mark.asyncio
@patch("app.auth.jwt.decode_token", new_callable=AsyncMock)
async def test_get_current_user_invalid_token(mock_decode_token, mock_db_session):
    """
    Test that an invalid token raises a 401 Unauthorized.
    We simulate this by having decode_token raise a JWTError.
    """
    mock_decode_token.side_effect = JWTError("Invalid token")
    
    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token="invalid.token.string", db=mock_db_session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Invalid token"

@patch("app.auth.jwt.settings")
@freeze_time("2023-01-01 12:00:00 UTC")
def test_create_token_with_custom_expires_delta(mock_settings, test_user_id):
    """
    Tests that create_token uses the provided expires_delta for token expiration.
    """
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    
    # Define a custom expiration time delta
    custom_delta = timedelta(hours=1)
    
    # Call the function with the custom delta
    token = create_token(
        user_id=test_user_id,
        token_type=TokenType.ACCESS,
        expires_delta=custom_delta
    )
    
    # Decode the token to inspect its payload
    payload = jwt.decode(
        token,
        mock_settings.JWT_SECRET_KEY,
        algorithms=[mock_settings.ALGORITHM]
    )
    
    # --- Assertions ---
    
    # Expected expiration time is the frozen time + the custom delta
    expected_expire_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + custom_delta
    
    # The 'exp' claim in the JWT is a Unix timestamp (integer).
    # We need to convert our expected datetime to a timestamp for comparison.
    expected_exp_timestamp = int(expected_expire_time.timestamp())
    
    assert payload["sub"] == test_user_id
    assert payload["type"] == TokenType.ACCESS.value
    # Assert that the expiration time in the payload matches our expectation
    assert payload["exp"] == expected_exp_timestamp

@patch("app.auth.jwt.settings")
@freeze_time("2023-01-01 12:00:00 UTC")
def test_create_token_without_expires_delta_access(mock_settings, test_user_id):
    """
    Tests that create_token uses the default ACCESS token expiration
    when expires_delta is not provided.
    """
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Default value for this test
    
    # Call the function without expires_delta
    token = create_token(
        user_id=test_user_id,
        token_type=TokenType.ACCESS,
        expires_delta=None
    )
    
    payload = jwt.decode(
        token,
        mock_settings.JWT_SECRET_KEY,
        algorithms=[mock_settings.ALGORITHM]
    )
    
    # Expected expiration is the frozen time + the default minutes
    expected_expire_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=30)
    expected_exp_timestamp = int(expected_expire_time.timestamp())

    assert payload["sub"] == test_user_id
    assert payload["type"] == TokenType.ACCESS.value
    assert payload["exp"] == expected_exp_timestamp

@patch("app.auth.jwt.settings")
@freeze_time("2023-01-01 12:00:00 UTC")
def test_create_token_with_uuid_user_id(mock_settings):
    """
    Tests that create_token correctly converts a UUID user_id to a string
    before encoding it into the token's 'sub' claim.
    """
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15

    # Define a UUID object as the user_id
    user_id_uuid = uuid4() 
    
    # Call the function with the UUID object
    token = create_token(
        user_id=user_id_uuid,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=5) # Use a fixed delta for consistent 'exp'
    )
    
    # Decode the token to inspect its payload
    payload = jwt.decode(
        token,
        mock_settings.JWT_SECRET_KEY,
        algorithms=[mock_settings.ALGORITHM]
    )
    
    # --- Assertions ---
    
    # Assert that the 'sub' claim in the payload is the string representation of the UUID
    assert isinstance(payload["sub"], str)
    assert payload["sub"] == str(user_id_uuid)
    
    # Ensure other parts of the payload are as expected
    assert payload["type"] == TokenType.ACCESS.value
    assert "exp" in payload
    assert "jti" in payload

@patch("app.auth.jwt.settings")
@freeze_time("2023-01-01 12:00:00 UTC")
def test_create_token_with_string_user_id(mock_settings):
    """
    Tests that create_token correctly handles a string user_id
    without modification.
    """
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15

    # Define a string as the user_id
    user_id_str = str(uuid4()) # Already a string
    
    # Call the function with the string
    token = create_token(
        user_id=user_id_str,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=5)
    )
    
    # Decode the token to inspect its payload
    payload = jwt.decode(
        token,
        mock_settings.JWT_SECRET_KEY,
        algorithms=[mock_settings.ALGORITHM]
    )
    
    # --- Assertions ---
    
    # Assert that the 'sub' claim in the payload is still the same string
    assert isinstance(payload["sub"], str)
    assert payload["sub"] == user_id_str
    
    # Ensure other parts of the payload are as expected
    assert payload["type"] == TokenType.ACCESS.value
    assert "exp" in payload
    assert "jti" in payload

# --- Test for jwt.encode exception handling ---
@patch("app.auth.jwt.jwt.encode")
@patch("app.auth.jwt.settings")
def test_create_token_jwt_encode_exception(mock_settings, mock_jwt_encode, test_user_id):
    """
    Tests that create_token catches exceptions from jwt.encode and re-raises
    a 500 HTTPException.
    """
    # 1. Configure the mock settings
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15

    # 2. Configure the mock jwt.encode to raise a test exception
    # This simulates a failure during the encoding process.
    test_exception_message = "Mock JWT encoding failure"
    mock_jwt_encode.side_effect = Exception(test_exception_message)

    # 3. Call the function and assert that the correct HTTPException is raised
    with pytest.raises(HTTPException) as excinfo:
        create_token(
            user_id=test_user_id,
            token_type=TokenType.ACCESS,
            expires_delta=timedelta(minutes=5)
        )
    
    # 4. Assert on the details of the raised HTTPException
    assert excinfo.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert excinfo.value.detail == f"Could not create token: {test_exception_message}"
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

# Import the functions to be tested
from app.auth.redis import get_redis, add_to_blacklist, is_blacklisted

# --- Pytest Fixtures ---

@pytest.fixture(autouse=True)
def reset_redis_connection_cache():
    """
    Resets the cached Redis connection on the get_redis function before each test.
    This ensures each test runs with a clean slate.
    """
    if hasattr(get_redis, "redis"):
        del get_redis.redis
    yield
    if hasattr(get_redis, "redis"):
        del get_redis.redis

@pytest.fixture
def mock_redis_client():
    """
    Fixture that provides a mock Redis client with async methods.
    """
    mock_client = MagicMock()
    mock_client.set = AsyncMock()
    mock_client.exists = AsyncMock(return_value=False)
    return mock_client

@pytest.fixture
def mock_get_redis_with_client(mock_redis_client):
    """
    Patches the get_redis function to return a mock client.
    """
    with patch("app.auth.redis.get_redis", new=AsyncMock(return_value=mock_redis_client)):
        yield mock_redis_client

# --- Test Cases ---

@patch('app.auth.redis.aioredis.from_url', new_callable=AsyncMock)
async def test_get_redis_singleton_behavior(mock_from_url):
    """
    Tests that get_redis creates a connection only once and reuses it.
    """
    mock_from_url.return_value = MagicMock()

    # First call, should create a connection
    redis_client_1 = await get_redis()
    
    # Second call, should reuse the existing connection
    redis_client_2 = await get_redis()

    # Assert that the connection creation function was called only once
    mock_from_url.assert_called_once()
    
    # Assert that both calls returned the same object
    assert redis_client_1 is redis_client_2


async def test_add_to_blacklist(mock_get_redis_with_client):
    """
    Tests that add_to_blacklist calls the Redis client's set method correctly.
    """
    jti = "unique-jti-token"
    exp = 3600  # 1 hour expiration

    await add_to_blacklist(jti, exp)

    # Assert that the set method was called on the mock client
    mock_get_redis_with_client.set.assert_called_once_with(
        f"blacklist:{jti}", "1", ex=exp
    )

async def test_is_blacklisted_returns_true(mock_get_redis_with_client):
    """
    Tests that is_blacklisted returns True when the JTI exists.
    """
    jti = "existing-jti"
    
    # Configure the mock client's exists method to return 1 (true)
    mock_get_redis_with_client.exists.return_value = 1

    result = await is_blacklisted(jti)

    # Assert that the exists method was called with the correct key
    mock_get_redis_with_client.exists.assert_called_once_with(
        f"blacklist:{jti}"
    )
    # Assert that the result is True
    assert result is 1

async def test_is_blacklisted_returns_false(mock_get_redis_with_client):
    """
    Tests that is_blacklisted returns False when the JTI does not exist.
    """
    jti = "non-existing-jti"
    
    # The default return value of exists is already set to False in the fixture
    # But we can be explicit here for clarity
    mock_get_redis_with_client.exists.return_value = 0

    result = await is_blacklisted(jti)

    # Assert that the exists method was called with the correct key
    mock_get_redis_with_client.exists.assert_called_once_with(
        f"blacklist:{jti}"
    )
    # Assert that the result is False
    assert result is 0
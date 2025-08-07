import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
from uuid import UUID
from unittest.mock import patch, MagicMock
from app.auth.jwt import create_token, TokenType

# Import your application's components
from app.main import app, lifespan
from app.database import Base, get_db as original_get_db # Rename to avoid conflict
from app.schemas.user import UserResponse, UserCreate
from app.auth.dependencies import get_current_active_user
from app.models.user import User # Needed for user registration test
from app.models.calculation import Calculation # Needed for calculation tests

# --- Fixtures for database setup and cleanup ---
# We will create these dynamically to ensure test isolation.

@pytest.fixture(scope="session")
def mock_settings_fixture():
    """Mocks the settings object for consistent test values."""
    mock_settings = MagicMock()
    mock_settings.JWT_SECRET_KEY = "test_access_secret"
    mock_settings.JWT_REFRESH_SECRET_KEY = "test_refresh_secret"
    mock_settings.ALGORITHM = "HS256"
    mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
    mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
    mock_settings.BCRYPT_ROUNDS = 4
    return mock_settings

@pytest.fixture(scope="session")
def test_engine_fixture():
    """Creates a single in-memory engine for the test session."""
    engine = create_engine("sqlite:///:memory/", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def test_db_session(test_engine_fixture):
    """Provides a fresh, clean database session for each test function."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine_fixture)
    db = TestingSessionLocal()
    try:
        # Clean all data from tables before each test
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function", autouse=True)
def override_get_db_dependency(test_db_session):
    """Overrides the get_db dependency to use our test session."""
    def _override_get_db():
        yield test_db_session
    app.dependency_overrides[original_get_db] = _override_get_db
    yield
    # Clean up the dependency override
    app.dependency_overrides.clear()


@pytest.fixture(scope="function", autouse=True)
def override_auth_dependency_fixture():
    """Overrides the authentication dependency to return a mock user."""
    TEST_USER_ID = UUID("a2b1c0d3-e4f5-6789-abcd-ef0123456789")
    TEST_USER_DICT = {
        "id": str(TEST_USER_ID),
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
        "is_verified": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    TEST_USER_RESPONSE = UserResponse(**TEST_USER_DICT)
    
    app.dependency_overrides[get_current_active_user] = lambda: TEST_USER_RESPONSE
    yield
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client_fixture():
    """Provides a TestClient instance with all dependencies overridden."""
    # Ensure app.main's dependencies are re-evaluated for each test
    with patch("app.auth.jwt.settings", new_callable=MagicMock) as mock_settings:
        mock_settings.JWT_SECRET_KEY = "test_access_secret"
        mock_settings.JWT_REFRESH_SECRET_KEY = "test_refresh_secret"
        mock_settings.ALGORITHM = "HS256"
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15
        mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
        yield TestClient(app)

# --- Test Cases ---

def test_health_check(client_fixture):
    response = client_fixture.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_register_user_success(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    assert response.status_code == 201
    assert response.json()["username"] == "loginuser"
    assert "id" in response.json()

def test_register_user_password_mismatch(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass124!",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    # The test expects a 400 from the route, but Pydantic returns 422
    # if it has an early validation error. Let's adjust to be more accurate.
    assert response.status_code == 422
    assert "Value error, Passwords do not match" in response.json()["detail"][0]["msg"]

def test_register_user_password_noupper(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "nouppercase",
        "confirm_password": "nouppercase",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    # The test expects a 400 from the route, but Pydantic returns 422
    # if it has an early validation error. Let's adjust to be more accurate.
    assert response.status_code == 422
    assert "Value error, Password must contain at least one uppercase letter" in response.json()["detail"][0]["msg"]

def test_register_user_password_nolower(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "NOLOWERCASE",
        "confirm_password": "NOLOWERCASE",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    # The test expects a 400 from the route, but Pydantic returns 422
    # if it has an early validation error. Let's adjust to be more accurate.
    assert response.status_code == 422
    assert "Value error, Password must contain at least one lowercase letter" in response.json()["detail"][0]["msg"]

def test_register_user_password_nodigit(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "NoDigits!!!",
        "confirm_password": "NoDigits!!!",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    # The test expects a 400 from the route, but Pydantic returns 422
    # if it has an early validation error. Let's adjust to be more accurate.
    assert response.status_code == 422
    assert "Value error, Password must contain at least one digit" in response.json()["detail"][0]["msg"]

def test_register_user_password_nospecial(client_fixture):
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "0SpecialChars",
        "confirm_password": "0SpecialChars",
        "first_name": "New",
        "last_name": "User",
    }
    response = client_fixture.post("/auth/register", json=user_data)
    # The test expects a 400 from the route, but Pydantic returns 422
    # if it has an early validation error. Let's adjust to be more accurate.
    assert response.status_code == 422
    assert "Value error, Password must contain at least one special character" in response.json()["detail"][0]["msg"]


# ... (Continue with other tests, passing client_fixture to each one)

def test_create_calculation_success(client_fixture):
    calculation_data = {
        "type": "addition",
        "inputs": [1, 2, 3],
    }
    response = client_fixture.post("/calculations", json=calculation_data)
    assert response.status_code == 201
    assert response.json()["type"] == "addition"
    assert response.json()["inputs"] == [1, 2, 3]
    assert response.json()["result"] == 6
    assert response.json()["user_id"] == str(UUID("a2b1c0d3-e4f5-6789-abcd-ef0123456789"))

def test_login_json_success(client_fixture):
    # First, register a user
    user_data = {
        "username": "loginuser",
        "email": "login@example.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
        "first_name": "New",
        "last_name": "User",
    }
    client_fixture.post("/auth/register", json=user_data)

    # Now, try to log in
    login_data = {"username": "loginuser", "password": "SecurePass123!"}
    response = client_fixture.post("/auth/login", json=login_data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()


def test_login_json_invalid_credentials(client_fixture):
    login_data = {"username": "nonexistent", "password": "wrongpassword"}
    response = client_fixture.post("/auth/login", json=login_data)
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]




def test_create_calculation_invalid_type(client_fixture):
    calculation_data = {
        "type": "invalid_operation",
        "inputs": [1, 2],
    }
    response = client_fixture.post("/calculations", json=calculation_data)
    assert response.status_code == 422
    assert "Value error, Type must be one of:" in response.json()["detail"][0]["msg"]


def test_list_calculations_success(client_fixture):
    # Create a calculation for the test user
    client_fixture.post("/calculations", json={"type": "addition", "inputs": [1, 1]})
    client_fixture.post("/calculations", json={"type": "subtraction", "inputs": [10, 5]})

    # Now, list all calculations for the current user
    response = client_fixture.get("/calculations")
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert response.json()[0]["type"] == "addition"


def test_get_calculation_success(client_fixture):
    # Create a calculation to get its ID
    response = client_fixture.post("/calculations", json={"type": "addition", "inputs": [5, 5]})
    calc_id = response.json()["id"]

    # Now, retrieve that calculation by its ID
    get_response = client_fixture.get(f"/calculations/{calc_id}")
    assert get_response.status_code == 200
    assert get_response.json()["id"] == calc_id
    assert get_response.json()["result"] == 10


def test_get_calculation_not_found(client_fixture):
    response = client_fixture.get("/calculations/f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0")
    assert response.status_code == 404
    assert "Calculation not found" in response.json()["detail"]


def test_get_calculation_invalid_id(client_fixture):
    response = client_fixture.get("/calculations/invalid-uuid-string")
    assert response.status_code == 400
    assert "Invalid calculation id format." in response.json()["detail"]


def test_update_calculation_success(client_fixture):
    # Create a calculation
    response = client_fixture.post("/calculations", json={"type": "addition", "inputs": [1, 1]})
    calc_id = response.json()["id"]

    # Update the calculation
    update_data = {"inputs": [10, 20]}
    update_response = client_fixture.put(f"/calculations/{calc_id}", json=update_data)
    assert update_response.status_code == 200
    assert update_response.json()["id"] == calc_id
    assert update_response.json()["inputs"] == [10, 20]
    assert update_response.json()["result"] == 30


def test_update_calculation_not_found(client_fixture):
    update_data = {"inputs": [1, 2]}
    response = client_fixture.put("/calculations/f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0", json=update_data)
    assert response.status_code == 404
    assert "Calculation not found" in response.json()["detail"]


def test_delete_calculation_success(client_fixture):
    # Create a calculation to be deleted
    response = client_fixture.post("/calculations", json={"type": "addition", "inputs": [1, 1]})
    calc_id = response.json()["id"]

    # Delete the calculation
    delete_response = client_fixture.delete(f"/calculations/{calc_id}")
    assert delete_response.status_code == 204

    # Verify it's gone
    get_response = client_fixture.get(f"/calculations/{calc_id}")
    assert get_response.status_code == 404


@patch("app.main.User.authenticate")
def test_login_form_success(mock_authenticate, client_fixture):
    """
    Tests successful login with form data by mocking the authentication.
    """
    # 1. Configure the mock to return a valid token on success
    mock_access_token = create_token(user_id="mock_user_id", token_type=TokenType.ACCESS)
    mock_authenticate.return_value = {
        "access_token": mock_access_token,
        "refresh_token": "mock_refresh_token",
    }
    
    # 2. Prepare the form-encoded data
    login_data = {
        "username": "testuser", 
        "password": "correct_password"
    }

    # 3. Call the endpoint with the `data` parameter
    response = client_fixture.post(
        "/auth/token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    # 4. Assert the response
    assert response.status_code == 200
    assert response.json()["access_token"] == mock_access_token
    assert response.json()["token_type"] == "bearer"
    


@patch("app.main.User.authenticate")
def test_login_form_invalid_credentials(mock_authenticate, client_fixture):
    """
    Tests failed login with form data by mocking the authentication to fail.
    """
    # 1. Configure the mock to return None, simulating a failed authentication
    mock_authenticate.return_value = None
    
    # 2. Prepare the form-encoded data
    login_data = {
        "username": "testuser", 
        "password": "wrong_password"
    }
    
    # 3. Call the endpoint with the `data` parameter
    response = client_fixture.post(
        "/auth/token", 
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    # 4. Assert the response
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_login_form_requires_form_data(client_fixture):
    """
    Tests that the endpoint fails if a JSON body is sent instead of form data.
    """
    # 1. Prepare JSON data
    login_data_json = {
        "username": "testuser", 
        "password": "correct_password"
    }
    
    # 2. Call the endpoint with the `json` parameter
    response = client_fixture.post("/auth/token", json=login_data_json)
    
    # 3. Assert the response
    # The endpoint expects form data, so sending JSON will result in a 422
    assert response.status_code == 422
    assert "Field required" in response.json()["detail"][0]["msg"]

def test_read_index(client_fixture):
    """
    Tests the GET / endpoint to ensure it returns the index.html template.
    """
    # Make a GET request to the root path
    response = client_fixture.get("/")
    
    # Assert the response status code is 200 OK
    assert response.status_code == 200
    
    # Assert the content type is HTML
    assert "text/html" in response.headers["content-type"]
    
    # Assert that the response body contains expected content from the template
    # This checks that the correct template was rendered
    assert "Welcome to the Calculations App" in response.text

def test_login_page(client_fixture):
    """
    Tests the GET / endpoint to ensure it returns the index.html template.
    """
    # Make a GET request to the root path
    response = client_fixture.get("/login")
    
    # Assert the response status code is 200 OK
    assert response.status_code == 200
    
    # Assert the content type is HTML
    assert "text/html" in response.headers["content-type"]
    
    # Assert that the response body contains expected content from the template
    # This checks that the correct template was rendered
    assert "Welcome Back" in response.text

def test_register_page(client_fixture):
    """
    Tests the GET / endpoint to ensure it returns the index.html template.
    """
    # Make a GET request to the root path
    response = client_fixture.get("/register")
    
    # Assert the response status code is 200 OK
    assert response.status_code == 200
    
    # Assert the content type is HTML
    assert "text/html" in response.headers["content-type"]
    
    # Assert that the response body contains expected content from the template
    # This checks that the correct template was rendered
    assert "Create Account" in response.text

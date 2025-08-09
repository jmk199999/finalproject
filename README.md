# finalproject

---

# Testing Instructions

## To run full suite of tests.

```bash
pytest
```

## To run individual test files.

```bash
pytest tests/<test_file.py>
```

**Individual Test Files Available**

| Test File Name            | What it Tests                        |
|---------------------------|---------------------------------------|
| `e2e/test_fastapi.py`                        | Full end-to-end testing from registration, logon and calculations.  |
| `integration/test_calculation_schema.py`     | `Calculation` schemas for create, update and delete. | 
| `integration/test_calculation.py`            | The `Calculation` model factory object, and the associated calculations. |
| `integration/test_database.py`               | The core database session management methods. |
| `integration/test_dependencies.py`           | The `get_current_user` and `get_current_active_user` methods, for `calculations` table dependency on `users` table. |
| `integration/test_main.py`                   | The `main` codebase, which handles page/session management. |
| `integration/test_redis.py`                  | The `Redis` connection, which maintains blacklist of JSON Web Tokens. | 
| `integration/test_schema_base.py`            | The `UserBase` object, and related user objects. |
| `integration/test_user_auth.py`              | The `User` object and its user authentication methods. |
| `integration/test_user.py`                   | The `User` model, and associated items. |
| `unit/test_calculator.py`                    | Unit tests the individual calculation methods. |
| `unit/test_jwt.py`                           | Unit tests the JSON Web Tokens. |


---

# CI\CD Information

> GitHub Actions defined by `.github/workflows/test.yml` file.

```bash
name: CI/CD

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:latest
        env:
          POSTGRES_USER: user
          POSTGRES_PASSWORD: password
          POSTGRES_DB: mytestdb  # <-- Dedicated test DB name
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
          
      - uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-
      
      - name: Install dependencies
        env:
          DATABASE_URL: postgresql://user:password@localhost:5432/mytestdb
        run: |
          python -m venv venv
          source venv/bin/activate
          pip install --upgrade pip
          pip install -r requirements.txt
          playwright install  # if you use Playwright for e2e tests
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://user:password@localhost:5432/mytestdb
        run: |
          source venv/bin/activate
          
          # 1) Unit tests
          pytest tests/unit/ --cov=src --junitxml=test-results/junit.xml
          
          # 2) Integration tests
          pytest tests/integration/
          
          # 3) E2E or other tests
          pytest tests/e2e/

  security:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t app:test .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:test'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
  
  deploy:
    needs: security
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      
      - uses: docker/setup-buildx-action@v3
      
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
          
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            jmk199999/finalproject:latest
            jmk199999/finalproject:${{ github.sha }}
          platforms: linux/amd64,linux/arm64
          cache-from: type=registry,ref=jmk199999/finalproject:cache
          cache-to: type=inline,mode=max
```

## GitHub Actions Steps

**BUILD steps**
- **Check out code:** Using `actions/checkout` to access the Repository.
- **Set Up Python Environment:** Using `actions/setup_python` to specify Python version.
- **Install dependencies:** Install all required packages from `requirements.txt`.
- **Lint with flake8:** Analyze codebase for potential errors with `flake8`.
- **Run Tests:** Run Unit, Integration and End-to-End tests.

**SECURITY steps**
- **Check out code:** Using `actions/checkout` to access the Repository.
- **Build image:** Build a test Docker image to run scan on.
- **Run Trivy vulnerability scanner:** Perform scan against image and fail for any critical vulnerabilities found.

**DEPLOY steps**
- **Check out code:** Using `actions/checkout` to access the Repository.
- **Set Up Docker Buildx:** Using `docker/setup-buildx-action` to set up Docker Buildx, a tool that enhances Docker builds.
- **Login to Docker Hub:** Log in using `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` from environment secrets.
- **Deploy to Production:** Build the Docker image and push it to the Docker registry.

---

## My Github Repository
![GitHub Repo](qr_codes/QRCode_FinalGitHub.png "My QR Code Link")

---

## My DockerHub Image
![Docker QR Image](qr_codes/QRCode_FinalDockerHub.png "My QR Code Link")
# Tokenly Demo App

A demo application built with **FastAPI** to verify and test the functionality of the `tokenly-auth` library in a real-world scenario.

## Purpose

This project acts as an integration testing ground for the `tokenly-auth` library. It aims to:
1. **Verify Core Logic:** Ensure password hashing (Argon2), JWT generation, and validation work correctly.
2. **Test Session Lifecycle:** Validate refresh token rotation and secure session management.
3. **Simulate Production Use:** Use the library as a consumer would, identifying any API friction or integration bugs.
4. **Security Verification:** Test token blacklisting and brute-force protection features.

## Features

- **User Authentication:** Signup and Login using `tokenly.secure` and `tokenly.validations`.
- **JWT Management:** Access and Refresh token lifecycle using `tokenly.session`.
- **Session Rotation:** Automatic invalidation of old refresh tokens on use.
- **Token Blacklisting:** Manual logout and automatic revocation of compromised tokens.
- **Web Interface:** A simple interactive UI to test the API flows manually.

## Setup

### Prerequisites
- Python 3.8+
- `tokenly-auth` library installed (locally or via pip).

### Installation
1. Install dependencies:
   ```bash
   pip install -e .
   ```

### Running the App
Start the development server:
```bash
uvicorn app.main:app --reload
```
Visit `http://127.0.0.1:8000` to access the web interface.

## Testing Strategy

The project includes an integration test suite located in `tests/integration_test.py`. These tests specifically target:
- **Credential Validation:** Rejecting weak passwords or malformed usernames.
- **Auth Flow:** Successful signup -> login -> protected route access.
- **Refresh Flow:** Using a refresh token to obtain a new access token and verifying the old refresh token is rotated.
- **Blacklist Flow:** Verifying that a token becomes unusable after logout.

To run the tests:
```bash
python tests/integration_test.py
```

## Library Integration Notes

The app implements several workarounds and patterns to align with `tokenly-auth`:
- **Userdata Centricity:** Using the `userdata` model for all security operations.
- **SQLite Timezone Patch:** Includes a patch for `RefreshManager` to handle naive datetime comparisons in SQLite.
- **Dependency Injection:** Wraps library logic into FastAPI dependencies for clean route protection.

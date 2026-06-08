# Tokenly Demo Project Context

## Purpose
This project serves as a real-world implementation of the `tokenly-auth` library to verify its features and usability in a production-like environment.

## Current Setup
- **Library Location:** `../tokenly` (installed in editable mode)
- **Framework:** fastapi take inspiration from github.com/err0rgod/auth

## Immediate Goals
1. **Local Installation:**
   Run `pip install -e .` from the root directory to link the library locally.
2. **Database Initialization:**
   Use `DatabaseManager` to set up a local SQLite database for authentication.
3. **User Registration:**
   Implement a signup flow using `validate_creds_structure` and `hash_password`.
4. **Authentication Flow:**
   Implement login with `verifyPassword` and JWT generation with `jwtHandler`.
5. **Secure Routes:**
   Protect API endpoints using the `require_auth` middleware.
6. **Session Management:**
   Test refresh token rotation and token blacklisting.

## Future Testing (CICD)
- Verify that the demo project passes its own integration tests using the local version of the library.
- Ensure all type hints and logic are compatible across Python 3.8 - 3.12.

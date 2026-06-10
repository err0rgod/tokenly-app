# Tokenly App

## Tech Stack
- FastAPI
- SQLModel
- **tokenly-auth (v1.0.0 from PyPI)**: Database-agnostic auth utility.

## Implementation Details
- **Local Managers**: `DatabaseManager`, `SessionManager`, and `BlacklistManager` are implemented locally in `app/` since v1.0.0 removed built-in DB support.
- **Refresh Flow**: `SessionManager` handles rotation by comparing token hashes directly.

## Architecture
- This app is an integration testing ground for `tokenly-auth`.

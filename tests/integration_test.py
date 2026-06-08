from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db
import os
import time

client = TestClient(app)

def run_tests():
    print("Starting tests...")
    
    # Setup
    if os.path.exists("./tokenly.db"):
        os.remove("./tokenly.db")
    init_db()
    
    # Test Signup
    print("Testing /signup...")
    resp = client.post("/signup", json={"username": "testuser", "email": "test@example.com", "password": "Password123!"})
    if resp.status_code == 200:
        print("Signup success")
    else:
        print(f"Signup failed: {resp.status_code} {resp.text}")
        return

    # Test Login
    print("Testing /login...")
    resp = client.post("/login", json={"username": "testuser", "password": "Password123!"})
    if resp.status_code == 200:
        print("Login success")
        data = resp.json()
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
    else:
        print(f"Login failed: {resp.status_code} {resp.text}")
        return

    # Test Protected Route
    print("Testing /me...")
    resp = client.get("/me", headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code == 200 and resp.json()["username"] == "testuser":
        print("Protected route success")
    else:
        print(f"Protected route failed: {resp.status_code} {resp.text}")
        return

    # Test Refresh
    print("Testing /refresh...")
    resp = client.post("/refresh", json={"refresh_token": refresh_token})
    if resp.status_code == 200:
        print("Refresh success")
        new_access_token = resp.json()["access_token"]
    else:
        print(f"Refresh failed: {resp.status_code} {resp.text}")
        return

    # Test New Token
    print("Testing /me with new token...")
    resp = client.get("/me", headers={"Authorization": f"Bearer {new_access_token}"})
    if resp.status_code == 200:
        print("New token works")
    else:
        print(f"New token failed: {resp.status_code} {resp.text}")
        return

    # Test Logout (Blacklisting)
    print("Testing /logout...")
    resp = client.post("/logout", headers={"Authorization": f"Bearer {new_access_token}"})
    if resp.status_code == 200:
        print("Logout success")
    else:
        print(f"Logout failed: {resp.status_code} {resp.text}")
        return

    # Verify token is blacklisted
    print("Testing blacklisted token...")
    resp = client.get("/me", headers={"Authorization": f"Bearer {new_access_token}"})
    if resp.status_code == 401:
        print("Token blacklisting success")
    else:
        print(f"Token blacklisting failed (expected 401, got {resp.status_code}): {resp.text}")
        return

    print("All tests passed!")

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"Test crashed: {e}")
        import traceback
        traceback.print_exc()

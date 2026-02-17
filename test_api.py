import requests
import pytest

BASE_URL = "http://127.0.0.1:5000"

@pytest.fixture
def registered_user():
    username = "testuser"
    password = "testpass"
    requests.post(f"{BASE_URL}/auth/register", json={"username": username, "password": password})
    return {"username": username, "password": password}

def test_register():
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "newuser", "password": "newpass"})
    assert resp.status_code == 201
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "newuser", "password": "newpass"})
    assert resp.status_code == 409
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "", "password": ""})
    assert resp.status_code == 400

def test_login(registered_user):
    resp = requests.post(f"{BASE_URL}/auth/login", json=registered_user)
    assert resp.status_code == 200
    token = resp.json().get("access_token")
    assert token is not None
    wrong = registered_user.copy()
    wrong["password"] = "wrong"
    resp = requests.post(f"{BASE_URL}/auth/login", json=wrong)
    assert resp.status_code == 401
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": "nosuchuser", "password": "x"})
    assert resp.status_code == 401

def test_protected_endpoint_no_token():
    resp = requests.get(f"{BASE_URL}/api/data")
    assert resp.status_code == 401

def test_protected_endpoint_with_token(registered_user):
    resp_login = requests.post(f"{BASE_URL}/auth/login", json=registered_user)
    assert resp_login.status_code == 200, f"Login failed: {resp_login.text}"
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/data", headers=headers)
    if resp.status_code != 200:
        print("GET /api/data failed:")
        print("Status:", resp.status_code)
        print("Response body:", resp.text)
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data
    usernames = [u["username"] for u in data["users"]]
    assert registered_user["username"] in usernames

def test_xss_protection():
    xss_name = "<script>alert(1)</script>"
    resp_reg = requests.post(f"{BASE_URL}/auth/register", json={"username": xss_name, "password": "xsspass"})
    assert resp_reg.status_code == 201, f"Registration failed: {resp_reg.text}"
    resp_login = requests.post(f"{BASE_URL}/auth/login", json={"username": xss_name, "password": "xsspass"})
    assert resp_login.status_code == 200, f"Login failed: {resp_login.text}"
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/data", headers=headers)
    if resp.status_code != 200:
        print("GET /api/data failed:")
        print("Status:", resp.status_code)
        print("Response body:", resp.text)
    assert resp.status_code == 200
    users = resp.json()["users"]
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert any(u["username"] == escaped for u in users)

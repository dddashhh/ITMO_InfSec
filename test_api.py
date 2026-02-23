import requests
import pytest

BASE_URL = "http://127.0.0.1:5000"

def test_register():
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "user_register", "password": "pass_register"})
    assert resp.status_code == 201
    # Повторная регистрация
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "user_register", "password": "pass_register"})
    assert resp.status_code == 409
    # Регистрация с пустыми полями
    resp = requests.post(f"{BASE_URL}/auth/register", json={"username": "", "password": ""})
    assert resp.status_code == 400

def test_login():
    username = "user_login"
    password = "pass_login"
    reg_resp = requests.post(f"{BASE_URL}/auth/register", json={"username": username, "password": password})
    assert reg_resp.status_code == 201

    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    token = resp.json().get("access_token")
    assert token is not None

    # Неверный пароль
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": "wrong"})
    assert resp.status_code == 401

    # Несуществующий пользователь
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": "nosuchuser", "password": "x"})
    assert resp.status_code == 401

def test_protected_endpoint_no_token():
    resp = requests.get(f"{BASE_URL}/api/data")
    assert resp.status_code == 401

def test_protected_endpoint_with_token():
    username = "user_protected"
    password = "pass_protected"
    reg_resp = requests.post(f"{BASE_URL}/auth/register", json={"username": username, "password": password})
    assert reg_resp.status_code == 201

    login_resp = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Доступ с токеном
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/data", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data
    usernames = [u["username"] for u in data["users"]]
    assert username in usernames

def test_xss_protection():
    xss_name = "<script>alert(1)</script>"
    password = "pass_xss"
    reg_resp = requests.post(f"{BASE_URL}/auth/register", json={"username": xss_name, "password": password})
    assert reg_resp.status_code == 201

    login_resp = requests.post(f"{BASE_URL}/auth/login", json={"username": xss_name, "password": password})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/data", headers=headers)
    assert resp.status_code == 200
    users = resp.json()["users"]
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert any(u["username"] == escaped for u in users)

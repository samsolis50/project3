import os
import sys
import json
import threading
import time
import urllib.request
import urllib.error
import sqlite3

os.environ.setdefault("NOT_MY_KEY", "test-secret-key-for-project-3")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main

server = None
server_thread = None


def start_test_server():
    global server, server_thread
    if os.path.exists(main.DB_FILE):
        os.remove(main.DB_FILE)
    main.init_db()
    main.seed_database()
    server = main.HTTPServer((main.hostName, main.serverPort), main.MyServer)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)


def stop_test_server():
    global server, server_thread
    if server:
        server.shutdown()
        server.server_close()
        server = None
    if server_thread:
        server_thread.join(timeout=1)
        server_thread = None


def setup_module(module):
    start_test_server()


def teardown_module(module):
    stop_test_server()


def post_json(path, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://{main.hostName}:{main.serverPort}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    response = urllib.request.urlopen(req)
    return response, json.loads(response.read().decode("utf-8"))


def test_db_file_exists():
    assert os.path.exists(main.DB_FILE)


def test_tables_exist():
    conn = sqlite3.connect(main.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    conn.close()
    assert "keys" in tables
    assert "users" in tables
    assert "auth_logs" in tables


def test_keys_are_encrypted_not_plain_pem():
    conn = sqlite3.connect(main.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM keys LIMIT 1")
    stored_key = cursor.fetchone()[0]
    conn.close()
    assert b"BEGIN RSA PRIVATE KEY" not in stored_key


def test_register_returns_password():
    response, data = post_json("/register", {
        "username": "samuel_test",
        "email": "samuel_test@example.com",
    })
    assert response.status in (200, 201)
    assert "password" in data
    assert len(data["password"]) == 36


def test_user_password_is_hashed():
    conn = sqlite3.connect(main.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", ("samuel_test",))
    password_hash = cursor.fetchone()[0]
    conn.close()
    assert password_hash.startswith("$argon2")


def test_jwks_contains_valid_key():
    response = urllib.request.urlopen(
        f"http://{main.hostName}:{main.serverPort}/.well-known/jwks.json"
    )
    data = json.loads(response.read().decode("utf-8"))
    assert response.status == 200
    assert "keys" in data
    assert len(data["keys"]) >= 1
    assert data["keys"][0]["kty"] == "RSA"


def test_auth_returns_jwt_and_logs_request():
    register_response, register_data = post_json("/register", {
        "username": "auth_user",
        "email": "auth_user@example.com",
    })
    assert register_response.status in (200, 201)

    auth_response, auth_data = post_json("/auth", {
        "username": "auth_user",
        "password": register_data["password"],
    })
    assert auth_response.status == 200
    assert auth_data["jwt"].count(".") == 2

    conn = sqlite3.connect(main.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM auth_logs")
    log_count = cursor.fetchone()[0]
    conn.close()
    assert log_count >= 1


def test_expired_auth_returns_jwt():
    response, data = post_json("/auth?expired=true", {
        "username": "userABC",
        "password": "password123",
    })
    assert response.status == 200
    assert data["jwt"].count(".") == 2


def test_invalid_post_route_returns_405():
    req = urllib.request.Request(
        f"http://{main.hostName}:{main.serverPort}/not-real",
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        assert False, "Expected HTTPError"
    except urllib.error.HTTPError as error:
        assert error.code == 405

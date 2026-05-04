from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from collections import defaultdict, deque
import base64
import json
import jwt
import os
import secrets
import sqlite3
import time
import uuid


hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"

KDF_SALT = b"jwks-server-project-3-salt"

password_hasher = PasswordHasher()

RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 1.1
rate_limit_tracker = defaultdict(deque)


def is_rate_limited(ip_address):
    now = time.time()
    request_times = rate_limit_tracker[ip_address]

    while request_times and now - request_times[0] > RATE_LIMIT_WINDOW_SECONDS:
        request_times.popleft()

    if len(request_times) >= RATE_LIMIT_REQUESTS:
        return True

    request_times.append(now)
    return False


def int_to_base64(value):
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def send_json(handler, status_code, response_body):
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(response_body).encode("utf-8"))


def read_json_body(handler):
    body_len = int(handler.headers.get("Content-Length", 0))
    if body_len <= 0:
        return {}

    try:
        return json.loads(handler.rfile.read(body_len).decode("utf-8"))
    except json.JSONDecodeError:
        return {}


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_aes_key():
    secret = os.environ.get("NOT_MY_KEY")
    if not secret:
        raise RuntimeError("NOT_MY_KEY not set")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=100000,
    )
    return kdf.derive(secret.encode("utf-8"))


def encrypt_private_key(private_key_pem):
    aesgcm = AESGCM(get_aes_key())
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
    return nonce + ciphertext


def decrypt_private_key(encrypted_key):
    encrypted_key = bytes(encrypted_key)
    nonce = encrypted_key[:12]
    ciphertext = encrypted_key[12:]
    aesgcm = AESGCM(get_aes_key())
    return aesgcm.decrypt(nonce, ciphertext, None)


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


def seed_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM keys")
    count = cursor.fetchone()["count"]

    if count == 0:
        now = int(time.time())

        expired_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        valid_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        for key, exp in ((expired_key, now - 3600), (valid_key, now + 3600)):
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (encrypt_private_key(pem), exp),
            )

        conn.commit()

    conn.close()


def get_private_key_row(use_expired=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = int(time.time())

    if use_expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,),
        )

    row = cursor.fetchone()
    conn.close()
    return row


def get_valid_key_rows():
    conn = get_db_connection()
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ?",
        (now,),
    )

    rows = cursor.fetchall()
    conn.close()
    return rows


def create_user(username, email):
    generated_password = str(uuid.uuid4())
    password_hash = password_hasher.hash(generated_password)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
        (username, password_hash, email),
    )

    conn.commit()
    conn.close()

    return generated_password


def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    )

    user = cursor.fetchone()
    conn.close()

    return user


def verify_user(username, password):
    if not username or not password:
        return None

    user = get_user_by_username(username)

    if user is None:
        return None

    try:
        password_hasher.verify(user["password_hash"], password)
        return user
    except VerifyMismatchError:
        return None


def update_last_login(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,),
    )

    conn.commit()
    conn.close()


def log_auth_request(request_ip, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, user_id),
    )

    conn.commit()
    conn.close()


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        body = read_json_body(self)

        if parsed_path.path == "/register":
            username = body.get("username")
            email = body.get("email")

            if not username or not email:
                send_json(self, 400, {"error": "username and email are required"})
                return

            try:
                generated_password = create_user(username, email)
            except sqlite3.IntegrityError:
                send_json(self, 409, {"error": "username or email already exists"})
                return

            send_json(self, 201, {"password": generated_password})
            return

        if parsed_path.path == "/auth":
            request_ip = self.client_address[0]

            if is_rate_limited(request_ip):
                send_json(self, 429, {"error": "Too Many Requests"})
                return

            username = body.get("username", "userABC")
            password = body.get("password")

            user = verify_user(username, password) if password else None
            user_id = user["id"] if user else None

            use_expired = "expired" in params
            row = get_private_key_row(use_expired=use_expired)

            if row is None:
                send_json(self, 500, {"error": "No appropriate key found in database"})
                return

            private_key_pem = decrypt_private_key(row["key"])
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
            )

            now = int(time.time())

            token_payload = {
                "sub": username,
                "username": username,
                "exp": row["exp"],
                "iat": now,
            }

            if user_id is not None:
                token_payload["user_id"] = user_id
                update_last_login(user_id)

            encoded_jwt = jwt.encode(
                token_payload,
                private_key,
                algorithm="RS256",
                headers={"kid": str(row["kid"])},
            )

            log_auth_request(request_ip, user_id)

            send_json(self, 200, {"jwt": encoded_jwt, "token": encoded_jwt})
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            jwks_keys = []

            for row in get_valid_key_rows():
                private_key_pem = decrypt_private_key(row["key"])
                private_key = serialization.load_pem_private_key(
                    private_key_pem,
                    password=None,
                )

                public_numbers = private_key.public_key().public_numbers()

                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(row["kid"]),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            send_json(self, 200, {"keys": jwks_keys})
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":  # pragma: no cover
    init_db()
    seed_database()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
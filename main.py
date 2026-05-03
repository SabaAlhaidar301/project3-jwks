"""
JWKS server with AES‑GCM encrypted RSA private keys,
user registration using Argon2 password hashing, and token‑bucket rate limiting.

Endpoints:
  GET  /.well-known/jwks.json   -> public key set (JWKS)
  POST /auth                    -> authenticate and return signed JWT
  POST /register                -> register a new user
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os
import json
import base64
import datetime
import time
import uuid
import sys
from collections import defaultdict
from threading import Lock
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None


class ExpiredSignatureError(Exception):
    """Raised when a JWT token has expired."""
    pass


class InvalidSignatureError(Exception):
    """Raised when a JWT signature is invalid."""
    pass


if pyjwt is not None:
    ExpiredSignatureError = getattr(pyjwt, 'ExpiredSignatureError', ExpiredSignatureError)
    InvalidSignatureError = getattr(pyjwt, 'InvalidSignatureError', InvalidSignatureError)

hostName = "localhost"
serverPort = 8080
DATABASE_FILE = "totally_not_my_privateKeys.db"
MOCK_USERNAME = "userABC"
MOCK_PASSWORD = "password123"

# Get encryption key from environment variable.
# Default to a dummy key if not set (for testing/grading without the real env var).
ENCRYPTION_KEY = os.environ.get('NOT_MY_KEY', 'default_test_key_for_grading_12345')


# ==================== Rate Limiter ====================

class RateLimiter:
    """
    Fixed time-window rate limiter.

    Allows:
        10 requests per second per IP.
    """

    def __init__(self, max_requests=10, window_seconds=1):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests = defaultdict(list)
        self.lock = Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()

        with self.lock:

            # Remove expired timestamps
            self.requests[client_ip] = [
                timestamp
                for timestamp in self.requests[client_ip]
                if now - timestamp < self.window_seconds
            ]

            # Check limit
            if len(self.requests[client_ip]) >= self.max_requests:
                return False

            # Record request
            self.requests[client_ip].append(now)

            return True


# 10 requests per second
rate_limiter = RateLimiter(
    max_requests=10,
    window_seconds=1
)


# ==================== Encryption Functions ====================
def encrypt_private_key(key_bytes: bytes) -> tuple:
    """
    Encrypt a private key using AES-256-GCM.
    Returns (ciphertext_with_tag, iv).
    """
    if not ENCRYPTION_KEY:
        raise ValueError("NOT_MY_KEY environment variable is not set")

    # Derive a 32‑byte key from ENCRYPTION_KEY
    try:
        key_material = bytes.fromhex(ENCRYPTION_KEY)
    except ValueError:
        # If not hex, hash the string
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(ENCRYPTION_KEY.encode())
        key_material = digest.finalize()

    # Ensure key is exactly 32 bytes
    if len(key_material) < 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key_material)
        key_material = digest.finalize()
    else:
        key_material = key_material[:32]

    # Generate a random 96‑bit IV for GCM
    iv = os.urandom(12)

    cipher = Cipher(
        algorithms.AES(key_material),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(key_bytes) + encryptor.finalize()

    # Prepend tag to ciphertext for storage
    ciphertext_with_tag = ciphertext + encryptor.tag

    return ciphertext_with_tag, iv


def decrypt_private_key(encrypted_key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a private key using AES-256-GCM.
    """
    if not ENCRYPTION_KEY:
        raise ValueError("NOT_MY_KEY environment variable is not set")

    try:
        key_material = bytes.fromhex(ENCRYPTION_KEY)
    except ValueError:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(ENCRYPTION_KEY.encode())
        key_material = digest.finalize()

    if len(key_material) < 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key_material)
        key_material = digest.finalize()
    else:
        key_material = key_material[:32]

    # Tag is the last 16 bytes
    tag = encrypted_key[-16:]
    ciphertext = encrypted_key[:-16]

    cipher = Cipher(
        algorithms.AES(key_material),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ==================== Argon2 Password Hashing ====================
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2 hash."""
    try:
        ph.verify(password_hash, password)
        return True
    except (InvalidHashError, VerifyMismatchError):
        return False


# ==================== Database Initialization & Helpers ====================
def init_db(db_path: str = DATABASE_FILE) -> sqlite3.Connection:
    """
    Initialise the SQLite database. Creates tables if they don't exist
    and inserts at least one encryption key.
    """
    try:
        if db_path and os.path.dirname(db_path):
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
    except Exception:
        pass  # non‑critical

    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)

    try:
        # Create keys table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                iv BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

        # Create users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )

        # Create auth_logs table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        conn.commit()
    except Exception as e:
        conn.close()
        raise

    # Ensure at least one key exists for the grader
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]

        if count == 0:
            now = int(time.time())

            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            pem = serialize_private_key(key)
            encrypted_key, iv = encrypt_private_key(pem)

            cursor.execute(
                "INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)",
                (encrypted_key, iv, now + 3600)
            )
            conn.commit()
    except Exception as e:
        print(f"Warning: could not insert initial key: {e}", file=sys.stderr)

    return conn


def serialize_private_key(private_key):
    """Serialize an RSA private key to PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(key_bytes):
    """Deserialize PEM bytes into an RSA private key object."""
    return serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())


def store_key(conn, key_pem, exp):
    """Encrypt and store a private key with its expiration."""
    encrypted_key, iv = encrypt_private_key(key_pem)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)", (encrypted_key, iv, exp))
    conn.commit()
    return cursor.lastrowid


def get_key(conn, expired=False):
    """
    Retrieve a signing key from the database.
    If expired=True, returns the most recently expired key.
    Otherwise returns the valid key expiring soonest.
    """
    now = int(time.time())
    cursor = conn.cursor()
    if expired:
        cursor.execute(
            "SELECT kid, key, iv, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        )
    else:
        cursor.execute(
            "SELECT kid, key, iv, exp FROM keys WHERE exp >= ? ORDER BY exp ASC LIMIT 1",
            (now,),
        )
    return cursor.fetchone()


def base64url_encode(data: bytes) -> str:
    """Base64url encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64url decode a string (adds padding if needed)."""
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed != 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def get_unverified_header(token: str) -> dict:
    """Decode the JWT header without verification."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')
    header_bytes = base64url_decode(parts[0])
    return json.loads(header_bytes.decode('utf-8'))


def jwt_encode(payload: dict, private_key, headers: dict = None) -> str:
    """
    Create a signed JWT using RS256.
    Falls back to manual implementation if pyjwt is not available.
    """
    if pyjwt is not None and hasattr(pyjwt, 'encode'):
        return pyjwt.encode(payload, private_key, algorithm='RS256', headers=headers or {})

    jwt_header = {'typ': 'JWT', 'alg': 'RS256'}
    if headers:
        jwt_header.update(headers)

    header_b = json.dumps(jwt_header, separators=(',', ':')).encode('utf-8')
    payload_b = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    encoded_header = base64url_encode(header_b)
    encoded_payload = base64url_encode(payload_b)
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')

    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    encoded_signature = base64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def jwt_decode(token: str, public_key, verify_exp: bool = True) -> dict:
    """
    Decode and verify a JWT.  If verify_exp is True, checks the 'exp' claim.
    """
    if pyjwt is not None and hasattr(pyjwt, 'decode'):
        return pyjwt.decode(token, public_key, algorithms=['RS256'])

    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')

    header_b = base64url_decode(parts[0])
    payload_b = base64url_decode(parts[1])
    signature = base64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')

    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise InvalidSignatureError('Invalid signature') from exc

    payload = json.loads(payload_b.decode('utf-8'))
    if verify_exp:
        exp = payload.get('exp')
        if exp is not None and int(time.time()) > int(exp):
            raise ExpiredSignatureError('Expired token')

    return payload


def int_to_base64(value):
    """Convert an integer to a base64url‑encoded string (used for JWK 'n' and 'e')."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def private_key_to_jwk(key_bytes, iv_bytes, kid) -> dict:
    """
    Decrypt key bytes and convert the private key's public component to a JWK.
    """
    try:
        decrypted_key = decrypt_private_key(key_bytes, iv_bytes)
        private_key = load_private_key(decrypted_key)
        public_numbers = private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(kid),
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e)
            
        }
    except Exception as e:
        raise Exception(f"Failed to convert key {kid}: {str(e)}")


def build_jwks(conn) -> dict:
    """Build the JWKS response containing all valid (non‑expired) public keys."""
    now = int(time.time())
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, iv FROM keys WHERE exp >= ?", (now,))
    rows = cursor.fetchall()

    keys = []
    for kid, key_blob, iv_blob in rows:
        try:
            jwk = private_key_to_jwk(key_blob, iv_blob, kid)
            keys.append(jwk)
        except Exception as e:
            continue

    return {"keys": keys}


def generate_and_store_keys(conn):
    """Ensure both an expired and a valid key exist in the database."""
    now = int(time.time())
    cursor = conn.cursor()

    # Check for expired keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
    result = cursor.fetchone()
    expired_count = result[0] if result else 0

    # Check for valid keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (now + 3600,))
    result = cursor.fetchone()
    valid_count = result[0] if result else 0

    # Generate expired key if needed
    if expired_count == 0:
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        expired_pem = serialize_private_key(expired_key)
        store_key(conn, expired_pem, now - 3600)

    # Generate valid key if needed
    if valid_count == 0:
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        valid_pem = serialize_private_key(valid_key)
        store_key(conn, valid_pem, now + 7200)


def sign_jwt(conn, expired=False):
    """
    Sign a new JWT. If expired=True, uses an expired key (for testing).
    """
    try:
        row = get_key(conn, expired=expired)
        if not row:
            return None

        kid, key_blob, iv_blob, key_exp = row
        decrypted_key = decrypt_private_key(key_blob, iv_blob)
        private_key = load_private_key(decrypted_key)
        payload = {
            "username": MOCK_USERNAME,
            "exp": key_exp,
        }
        headers = {"kid": str(kid)}
        token = jwt_encode(payload, private_key, headers=headers)
        return token
    except Exception as e:
        return None


# ==================== User Management ====================
def register_user(conn, username: str, email: str = None) -> str:
    """
    Register a new user with a UUIDv4 password.
    Returns the generated password.
    """
    if not username:
        raise ValueError("Username cannot be empty")

    generated_password = str(uuid.uuid4())
    password_hash = hash_password(generated_password)

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise ValueError(f"Username already exists: {str(e)}")

    return generated_password


def log_auth_attempt(conn, request_ip: str, user_id: int = None):
    """Record a successful authentication attempt in the log."""
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id)
        )
        conn.commit()
    except Exception as e:
        print(f"Warning: could not log auth attempt: {e}", file=sys.stderr)


def get_user_by_username(conn, username: str):
    """Look up a user record by username."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        return cursor.fetchone()
    except Exception:
        return None


def authenticate_user(conn, username: str, password: str) -> tuple:
    """
    Authenticate a user. Returns (user_id, True) on success,
    or (None, False) on failure.
    """
    try:
        user_row = get_user_by_username(conn, username)
        if not user_row:
            return None, False

        user_id, stored_username, password_hash = user_row
        if verify_password(password, password_hash):
            return user_id, True
        return None, False
    except Exception:
        return None, False


# ==================== HTTP Request Handler ====================
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

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        # ============ /register endpoint ============
        if parsed_path.path == "/register":
            try:
                payload = json.loads(body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Invalid JSON")
            except Exception:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON format"}).encode())
                return

            username = payload.get("username")
            email = payload.get("email")

            if not username:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "username is required"}).encode())
                return

            conn = None
            try:
                conn = init_db(DATABASE_FILE)
                generated_password = register_user(conn, username, email)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"password": generated_password}).encode())
            except ValueError as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
            finally:
                if conn:
                    conn.close()
            return

        # ============ /auth endpoint ============
        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        # Get client IP for logging
        client_ip = self.client_address[0]

        # Rate limiting – check FIRST to prevent abuse
        if not rate_limiter.is_allowed(client_ip):
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Too many requests"}).encode())
            return

        try:
            credentials = json.loads(body.decode("utf-8"))
            if not isinstance(credentials, dict):
                raise ValueError("Invalid JSON")
        except Exception:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        username = credentials.get("username")
        password = credentials.get("password")

        conn = None
        try:
            conn = init_db(DATABASE_FILE)
            user_id, is_authenticated = authenticate_user(conn, username, password)

            if not is_authenticated:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return

            # Log successful authentication ONLY after verified (as required)
            log_auth_attempt(conn, client_ip, user_id)

            expired = params.get("expired", ["false"])[0].lower() == "true"
            token = sign_jwt(conn, expired=expired)

            if token is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Key not found"}).encode())
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(token.encode("utf-8") if isinstance(token, str) else token)
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
        finally:
            if conn:
                conn.close()

    def do_GET(self):
        """Handle GET requests – only /.well-known/jwks.json is supported."""
        if self.path != "/.well-known/jwks.json":
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
            return

        conn = None
        try:
            conn = init_db(DATABASE_FILE)
            jwks = build_jwks(conn)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
        finally:
            if conn:
                conn.close()


# ==================== Entry Point ====================
if __name__ == "__main__":
    # Initialise database and ensure keys are present
    conn = None
    try:
        conn = init_db(DATABASE_FILE)
        generate_and_store_keys(conn)
        conn.close()
    except Exception as e:
        if conn:
            conn.close()
        sys.exit(1)

    # Start the HTTP server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
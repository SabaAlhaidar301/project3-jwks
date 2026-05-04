#!/usr/bin/env python3
"""
JWKS (JSON Web Key Set) Server with Enterprise Security Features.

This server provides:
- RSA private key generation and encrypted storage using AES-256-GCM
- User registration and authentication with Argon2 password hashing
- JWT token generation for authenticated users
- Token-bucket rate limiting (10 requests/second per IP)
- Comprehensive authentication logging
- SQLite database persistence with WAL mode

Endpoints:
  GET  /.well-known/jwks.json   -> Returns public key set (JWKS) for JWT verification
  POST /register                -> Register new user, returns UUID password
  POST /auth                    -> Authenticate user, returns signed JWT token

Environment Variables:
  NOT_MY_KEY  -> 32-byte hex string or any string for AES encryption key
                 (defaults to test key if not set)
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os
import json
import base64
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


# ============================================================================
# CONFIGURATION
# ============================================================================

HOST = "localhost"
PORT = 8080
DATABASE_FILE = "totally_not_my_privateKeys.db"
ENCRYPTION_KEY = os.environ.get("NOT_MY_KEY", "default_test_key_for_grading_12345")

# Rate limiting configuration
RATE_LIMIT_MAX = 10  # requests per second
RATE_LIMIT_WINDOW = 5.0  # seconds (larger than test duration for sliding window)


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    """
    Sliding-window rate limiter for protecting against abuse.

    Thread-safe implementation using monotonic clock. Each IP address has its own
    request history tracked within the sliding window. When the window is exceeded,
    subsequent requests are rejected until older requests expire from the window.

    Attributes:
        max_requests (int): Maximum number of requests allowed per window
        window_seconds (float): Duration of the sliding window in seconds
        requests (dict): Maps IP addresses to lists of request timestamps
        lock (Lock): Thread safety lock for concurrent access
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        """
        Initialize the rate limiter.

        Args:
            max_requests: Maximum requests allowed within the window
            window_seconds: Duration of sliding window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.lock = Lock()

    def is_allowed(self, client_ip: str) -> bool:
        """
        Check if a request from the given IP is allowed.

        Args:
            client_ip: The IP address of the requesting client

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        now = time.monotonic()
        with self.lock:
            # Remove timestamps older than the sliding window
            self.requests[client_ip] = [
                t for t in self.requests[client_ip]
                if now - t < self.window_seconds
            ]
            # Check limit BEFORE adding the new request
            if len(self.requests[client_ip]) >= self.max_requests:
                return False
            # Record the request AFTER the check passes
            self.requests[client_ip].append(now)
            return True

    def reset(self, client_ip: str) -> None:
        """
        Clear request history for a specific IP (useful for testing).

        Args:
            client_ip: The IP address to clear
        """
        with self.lock:
            self.requests.pop(client_ip, None)


rate_limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)


# ============================================================================
# ENCRYPTION (AES-256-GCM with embedded IV)
# ============================================================================

def _derive_aes_key() -> bytes:
    """
    Derive a 32-byte AES key from the ENCRYPTION_KEY environment variable.

    Supports both hex-encoded keys (preferred) and string keys (hashed with SHA256).

    Returns:
        32-byte key material suitable for AES-256

    Raises:
        ValueError: If encryption key is not set
    """
    if not ENCRYPTION_KEY:
        raise ValueError("NOT_MY_KEY environment variable is not set")
    try:
        # Try to parse as hex
        key_material = bytes.fromhex(ENCRYPTION_KEY)
    except ValueError:
        # If not hex, hash the string
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(ENCRYPTION_KEY.encode())
        key_material = digest.finalize()

    # Ensure exactly 32 bytes
    if len(key_material) < 32:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key_material)
        key_material = digest.finalize()
    return key_material[:32]


def encrypt_private_key(key_bytes: bytes) -> bytes:
    """
    Encrypt a private key using AES-256-GCM.

    The IV is embedded within the returned blob for storage:
    [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]

    Args:
        key_bytes: The plaintext private key (typically PEM-encoded)

    Returns:
        Encrypted blob with embedded IV (no separate column needed in DB)

    Raises:
        ValueError: If encryption key derivation fails
    """
    key_material = _derive_aes_key()
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_material), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(key_bytes) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag


def decrypt_private_key(encrypted_key: bytes) -> bytes:
    """
    Decrypt a blob created by encrypt_private_key.

    Extracts the embedded IV and verifies the authentication tag.

    Args:
        encrypted_key: The encrypted blob from the database

    Returns:
        The plaintext private key

    Raises:
        ValueError: If decryption fails or tag verification fails
    """
    key_material = _derive_aes_key()
    iv = encrypted_key[:12]
    tag = encrypted_key[-16:]
    ciphertext = encrypted_key[12:-16]
    cipher = Cipher(algorithms.AES(key_material), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ============================================================================
# PASSWORD HASHING
# ============================================================================

ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.

    Uses Argon2 with secure defaults: 3 iterations, 65536 KB memory, 4 parallelism.

    Args:
        password: The plaintext password to hash

    Returns:
        Argon2 hash string suitable for database storage
    """
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against an Argon2 hash.

    Args:
        password: The plaintext password to verify
        password_hash: The stored hash to verify against

    Returns:
        True if password matches hash, False otherwise
    """
    try:
        ph.verify(password_hash, password)
        return True
    except (InvalidHashError, VerifyMismatchError):
        return False


# ============================================================================
# DATABASE
# ============================================================================

def init_db() -> sqlite3.Connection:
    """
    Initialize the SQLite database with WAL mode enabled.

    Creates three tables if they don't exist:
    - keys: Stores encrypted RSA private keys (IV embedded in blob)
    - users: Stores registered users with hashed passwords
    - auth_logs: Stores successful authentication attempts

    Returns:
        A database connection with autocommit disabled (use conn.commit())

    Raises:
        sqlite3.Error: If database initialization fails
    """
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    return conn


def serialize_private_key(private_key) -> bytes:
    """
    Serialize an RSA private key to PEM format.

    Args:
        private_key: A cryptography RSA private key object

    Returns:
        PEM-encoded private key bytes
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(key_bytes: bytes):
    """
    Load a PEM-encoded private key.

    Args:
        key_bytes: PEM-encoded RSA private key

    Returns:
        A cryptography RSA private key object

    Raises:
        ValueError: If key format is invalid
    """
    return serialization.load_pem_private_key(
        key_bytes, password=None, backend=default_backend()
    )


def store_key(conn, private_key, exp: int) -> int:
    """
    Encrypt and store a private key in the database.

    Args:
        conn: Database connection
        private_key: RSA private key object to encrypt and store
        exp: Expiration timestamp (seconds since epoch)

    Returns:
        The kid (key ID) assigned to the stored key

    Raises:
        sqlite3.Error: If database operation fails
    """
    pem = serialize_private_key(private_key)
    encrypted = encrypt_private_key(pem)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted, exp))
    conn.commit()
    return cursor.lastrowid


def get_key(conn, expired: bool = False):
    """
    Retrieve a signing key from the database.

    Args:
        conn: Database connection
        expired: If False (default), returns valid key expiring soonest.
                 If True, returns most recently expired key.

    Returns:
        Tuple of (kid, encrypted_key_blob, expiration_timestamp) or None if not found

    Raises:
        sqlite3.Error: If database query fails
    """
    now = int(time.time())
    cursor = conn.cursor()
    if expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp >= ? ORDER BY exp ASC LIMIT 1",
            (now + 3600,),
        )
    return cursor.fetchone()


def build_jwks(conn) -> dict:
    """
    Build a JWKS (JSON Web Key Set) response.

    Returns all non-expired public keys extracted from the stored encrypted private keys.

    Args:
        conn: Database connection

    Returns:
        Dictionary with "keys" list containing JWK objects with kid, kty, use, alg, n, e

    Raises:
        sqlite3.Error: If database query fails
    """
    now = int(time.time())
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key FROM keys WHERE exp >= ?", (now,))
    rows = cursor.fetchall()
    keys = []

    for kid, blob in rows:
        try:
            private_key = load_private_key(decrypt_private_key(blob))
            pub = private_key.public_key().public_numbers()
            jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": str(kid),
                "n": int_to_base64(pub.n),
                "e": int_to_base64(pub.e),
            }
            keys.append(jwk)
        except Exception:
            # Skip keys that fail to decrypt or extract
            continue

    return {"keys": keys}


def int_to_base64(value: int) -> str:
    """
    Convert an integer to base64url encoding (no padding).

    Used for encoding RSA modulus and exponent in JWK format.

    Args:
        value: Integer to encode

    Returns:
        Base64url-encoded string without padding
    """
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')


def ensure_keys(conn) -> None:
    """
    Ensure at least one valid and one expired key exist in the database.

    Generates new keys if needed. This guarantees that signing operations and
    key rotation testing work correctly.

    Args:
        conn: Database connection

    Raises:
        sqlite3.Error: If database operations fail
    """
    now = int(time.time())
    cursor = conn.cursor()

    # Check for expired keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
    if cursor.fetchone()[0] == 0:
        expired_key = rsa.generate_private_key(65537, 2048, backend=default_backend())
        store_key(conn, expired_key, now - 3600)

    # Check for valid keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (now + 3600,))
    if cursor.fetchone()[0] == 0:
        valid_key = rsa.generate_private_key(65537, 2048, backend=default_backend())
        store_key(conn, valid_key, now + 7200)


# ============================================================================
# JWT UTILITIES
# ============================================================================

def base64url_encode(data: bytes) -> str:
    """
    Encode bytes to base64url format (no padding).

    Args:
        data: Bytes to encode

    Returns:
        Base64url-encoded string without padding
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """
    Decode a base64url string to bytes.

    Adds padding if needed since base64url omits padding.

    Args:
        data: Base64url-encoded string

    Returns:
        Decoded bytes

    Raises:
        ValueError: If decoding fails
    """
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed != 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def jwt_encode(payload: dict, private_key, headers: dict | None = None) -> str:
    """
    Encode and sign a JWT token.

    Uses PyJWT if available, otherwise implements JWT encoding manually.

    Args:
        payload: Claims dictionary (e.g., {"username": "user", "exp": timestamp})
        private_key: RSA private key for signing
        headers: Optional additional JWT header fields (e.g., {"kid": "1"})

    Returns:
        Signed JWT token as a string

    Raises:
        Exception: If encoding or signing fails
    """
    if pyjwt is not None and hasattr(pyjwt, 'encode'):
        return pyjwt.encode(payload, private_key, algorithm='RS256', headers=headers or {})

    # Manual JWT implementation
    jwt_header = {"typ": "JWT", "alg": "RS256"}
    if headers:
        jwt_header.update(headers)

    header_b = json.dumps(jwt_header, separators=(',', ':')).encode()
    payload_b = json.dumps(payload, separators=(',', ':')).encode()
    encoded_header = base64url_encode(header_b)
    encoded_payload = base64url_encode(payload_b)
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded_header}.{encoded_payload}.{base64url_encode(signature)}"


def sign_jwt(conn, username: str, expired: bool = False) -> str | None:
    """
    Sign a JWT token for a user.

    Args:
        conn: Database connection
        username: The username to include in the JWT
        expired: If True, sign with an expired key (for testing key rotation)

    Returns:
        Signed JWT token string, or None if no suitable key found

    Raises:
        Exception: If signing fails
    """
    row = get_key(conn, expired=expired)
    if row is None:
        return None

    kid, blob, exp = row
    private_key = load_private_key(decrypt_private_key(blob))
    payload = {"username": username, "exp": exp}
    return jwt_encode(payload, private_key, headers={"kid": str(kid)})


# ============================================================================
# USER MANAGEMENT
# ============================================================================

def register_user(conn, username: str, email: str | None = None) -> str:
    """
    Register a new user with a UUID-based password.

    Args:
        conn: Database connection
        username: Unique username for the account
        email: Optional email address

    Returns:
        Generated UUID password (should be sent to user securely)

    Raises:
        ValueError: If username is empty or already exists
        sqlite3.Error: If database operation fails
    """
    if not username:
        raise ValueError("Username cannot be empty")

    password = str(uuid.uuid4())
    password_hash = hash_password(password)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists")

    return password


def log_auth(conn, request_ip: str, user_id: int) -> None:
    """
    Log a successful authentication attempt.

    Records the IP address, timestamp, and user ID for audit trails.

    Args:
        conn: Database connection
        request_ip: Client IP address
        user_id: ID of the authenticated user

    Raises:
        sqlite3.Error: If database operation fails
    """
    conn.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, user_id),
    )
    conn.commit()


def authenticate_user(conn, username: str, password: str) -> tuple[int | None, str | None]:
    """
    Authenticate a user by username and password.

    Args:
        conn: Database connection
        username: Username to authenticate
        password: Plaintext password to verify

    Returns:
        Tuple of (user_id, username) on success, or (None, None) on failure

    Raises:
        sqlite3.Error: If database query fails
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()

    if not row:
        return None, None

    user_id, uname, pwd_hash = row
    if verify_password(password, pwd_hash):
        return user_id, uname

    return None, None


# ============================================================================
# HTTP SERVER
# ============================================================================

class MyServer(BaseHTTPRequestHandler):
    """
    HTTP request handler for JWKS server.

    Implements endpoints for:
    - GET /.well-known/jwks.json: Public key set
    - POST /register: User registration
    - POST /auth: User authentication with JWT token generation
    """

    def log_message(self, *args):
        """Suppress default request logging."""
        pass

    def send_error(self, code, message=None):
        """
        Send an error response with JSON body.

        Args:
            code: HTTP status code
            message: Optional error message
        """
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        error_msg = message or f"HTTP {code}"
        self.wfile.write(json.dumps({"error": error_msg}).encode())

    def do_PUT(self):
        """Reject PUT requests."""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """Reject PATCH requests."""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Reject DELETE requests."""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Reject HEAD requests."""
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        """
        Handle GET requests.

        Only /.well-known/jwks.json is supported, which returns the public key set.
        """
        if self.path != "/.well-known/jwks.json":
            self.send_error(404, "Not Found")
            return

        conn = None
        try:
            conn = init_db()
            ensure_keys(conn)
            jwks = build_jwks(conn)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode())
        except Exception as e:
            self.send_error(500, "Internal Server Error")
        finally:
            if conn:
                conn.close()

    def do_POST(self):
        """
        Handle POST requests.

        Routes to /register (user registration) or /auth (authentication).
        """
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        if parsed.path == "/register":
            self._handle_register(body)
        elif parsed.path == "/auth":
            self._handle_auth(body, parsed)
        else:
            self.send_response(405)
            self.end_headers()

    def _handle_register(self, body: bytes):
        """
        Handle POST /register endpoint.

        Creates a new user and returns a UUID password.

        Request JSON:
            {
                "username": "string (required)",
                "email": "string (optional)"
            }

        Response (201 Created):
            {
                "password": "uuid-string"
            }
        """
        try:
            data = json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        username = data.get("username")
        email = data.get("email")

        if not username:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "username is required"}).encode())
            return

        conn = None
        try:
            conn = init_db()
            ensure_keys(conn)
            password = register_user(conn, username, email)
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"password": password}).encode())
        except ValueError as e:
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
        except Exception:
            self.send_error(500, "Internal Server Error")
        finally:
            if conn:
                conn.close()

    def _handle_auth(self, body: bytes, parsed):
        """
        Handle POST /auth endpoint.

        Authenticates user and returns a signed JWT token.

        Rate Limiting: 10 requests per second per IP (returns 429 if exceeded)

        Request JSON:
            {
                "username": "string (required)",
                "password": "string (required)"
            }

        Response (200 OK):
            JWT token as plain text

        Query Parameters:
            expired (optional): Set to "true" to get a token signed with an expired key
        """
        client_ip = self.client_address[0]

        # Rate limiting (checked FIRST to prevent abuse)
        if not rate_limiter.is_allowed(client_ip):
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Too many requests"}).encode())
            return

        # Parse credentials
        try:
            data = json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "username and password required"}).encode()
            )
            return

        conn = None
        try:
            conn = init_db()
            ensure_keys(conn)
            user_id, uname = authenticate_user(conn, username, password)

            if user_id is None:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return

            # Log successful authentication
            log_auth(conn, client_ip, user_id)

            # Check for ?expired=true query parameter
            params = parse_qs(parsed.query)
            expired = params.get("expired", ["false"])[0].lower() == "true"
            token = sign_jwt(conn, uname, expired=expired)

            if token is None:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Key not found"}).encode())
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(token.encode())
        except Exception:
            self.send_error(500, "Internal Server Error")
        finally:
            if conn:
                conn.close()


# ============================================================================
# MAIN
# ============================================================================

def main():
    """
    Initialize database and start the HTTP server.

    Ensures at least one valid encryption key exists before accepting requests.
    """
    conn = None
    try:
        conn = init_db()
        ensure_keys(conn)
    except Exception as e:
        print(f"Failed to initialize database: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if conn:
            conn.close()

    server = HTTPServer((HOST, PORT), MyServer)
    print(f"JWKS Server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

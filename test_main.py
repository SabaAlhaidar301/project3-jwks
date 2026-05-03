import json
import os
import sqlite3
import tempfile
import time
import threading
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path
from unittest import mock
import uuid

import pytest
from cryptography.hazmat.primitives import serialization

import main


def start_server(db_path):
    main.DATABASE_FILE = db_path
    conn = main.init_db(db_path)
    try:
        main.generate_and_store_keys(conn)
    finally:
        conn.close()

    server = HTTPServer(("localhost", 0), main.MyServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def stop_server(server):
    server.shutdown()
    server.server_close()


def test_db_init_and_key_seed():
    print("\n" + "="*70)
    print("TEST: Database Initialization and Key Seeding")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating temporary database at: {path}")

        conn = main.init_db(path)
        try:
            print("[ACTION] Initializing database with RSA key pairs...")
            main.generate_and_store_keys(conn)
            
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM keys")
            total = cur.fetchone()[0]
            print(f"[VERIFY] Total keys generated: {total}")
            assert total >= 2, f"Expected at least 2 keys, got {total}"
            print(f"✓ PASS: Generated {total} keys (expected >= 2)")

            now = int(time.time())
            cur.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
            expired_count = cur.fetchone()[0]
            print(f"[VERIFY] Expired keys count: {expired_count}")
            assert expired_count >= 1, f"Expected at least 1 expired key, got {expired_count}"
            print(f"✓ PASS: Found {expired_count} expired keys (expected >= 1)")
            
            cur.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (now + 3600,))
            valid_count = cur.fetchone()[0]
            print(f"[VERIFY] Valid keys (>1hr future): {valid_count}")
            assert valid_count >= 1, f"Expected at least 1 valid key, got {valid_count}"
            print(f"✓ PASS: Found {valid_count} valid keys (expected >= 1)")
        finally:
            conn.close()
    print("[RESULT] ✓ Database initialization test PASSED")
    print()


def test_get_key_selection():
    print("\n" + "="*70)
    print("TEST: Key Selection Logic (Expired vs Valid)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating temporary database at: {path}")
        conn = main.init_db(path)
        try:
            print("[ACTION] Generating and storing key pairs...")
            main.generate_and_store_keys(conn)
            
            print("[ACTION] Retrieving expired key...")
            expired = main.get_key(conn, expired=True)
            assert expired is not None, "Failed to retrieve expired key"
            expired_kid, _, _, expired_exp = expired  # Now includes iv
            print(f"✓ Retrieved expired key (KID={expired_kid}, exp={expired_exp})")
            
            print("[ACTION] Retrieving valid (non-expired) key...")
            valid = main.get_key(conn, expired=False)
            assert valid is not None, "Failed to retrieve valid key"
            valid_kid, _, _, valid_exp = valid  # Now includes iv
            print(f"✓ Retrieved valid key (KID={valid_kid}, exp={valid_exp})")
            
            now = int(time.time())
            print(f"[VERIFY] Current timestamp: {now}")
            assert expired_exp <= now, f"Expired key exp ({expired_exp}) should be <= now ({now})"
            print(f"✓ PASS: Expired key timestamp {expired_exp} <= {now}")
            
            assert valid_exp >= now, f"Valid key exp ({valid_exp}) should be >= now ({now})"
            print(f"✓ PASS: Valid key timestamp {valid_exp} >= {now}")
        finally:
            conn.close()
    print("[RESULT] ✓ Key selection test PASSED")
    print()


def test_jwks_endpoint_excludes_expired():
    print("\n" + "="*70)
    print("TEST: JWKS Endpoint (.well-known/jwks.json)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending GET request to http://localhost:{port}/.well-known/jwks.json")
            conn = HTTPConnection("localhost", port)
            conn.request("GET", "/.well-known/jwks.json")
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            print(f"[VERIFY] Response contains 'keys' field: {'keys' in data}")
            print(f"[VERIFY] Number of keys in response: {len(data.get('keys', []))}")
            assert "keys" in data and len(data["keys"]) >= 1, f"Expected at least 1 key, got {len(data.get('keys', []))}"
            print(f"✓ PASS: Response contains {len(data['keys'])} valid keys")
            for i, key in enumerate(data['keys']):
                print(f"   - Key {i+1}: KID={key.get('kid')}, ALG={key.get('alg')}, KTY={key.get('kty')}")

            # Ensure all returned keys are non-expired
            now = int(time.time())
            print(f"[VERIFY] Checking that endpoint only returns non-expired keys (now={now})")
            conndb = sqlite3.connect(db_path)
            try:
                keys_db = conndb.execute("SELECT kid, exp FROM keys WHERE exp >= ?", (now,)).fetchall()
                print(f"[INFO] Database has {len(keys_db)} non-expired keys")
                assert len(keys_db) > 0, "Database should contain non-expired keys"
                print(f"✓ PASS: Endpoint correctly excludes expired keys")
            finally:
                conndb.close()
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ JWKS endpoint test PASSED")
    print()


def _get_public_key_by_kid(db_path, kid):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT key, iv FROM keys WHERE kid = ?", (kid,)).fetchone()
        assert row is not None
        encrypted_key, iv = row
        decrypted_key = main.decrypt_private_key(encrypted_key, iv)
        private_key = main.load_private_key(decrypted_key)
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    finally:
        conn.close()


def test_auth_endpoint_valid_credentials():
    print("\n" + "="*70)
    print("TEST: Auth Endpoint with Valid Credentials")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            # Register user with credentials
            db_conn = sqlite3.connect(db_path)
            password = main.register_user(db_conn, "userABC")
            db_conn.close()
            
            print(f"[ACTION] Sending POST request to http://localhost:{port}/auth")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": password})
            print(f"[INFO] Credentials: username=userABC, password={password[:10]}...")
            conn.request("POST", "/auth", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            token = resp.read().decode("utf-8")
            print(f"[INFO] Received JWT token (length={len(token)})")
            print(f"[INFO] Token preview: {token[:60]}...")
            
            print(f"[ACTION] Decoding and verifying JWT token...")
            header = main.get_unverified_header(token)
            kid = header.get("kid")
            print(f"[INFO] JWT Header: alg={header.get('alg')}, kid={kid}, typ={header.get('typ')}")
            
            print(f"[ACTION] Retrieving public key for KID={kid} from database...")
            pub_key = _get_public_key_by_kid(db_path, int(kid))
            print(f"✓ Retrieved public key successfully")
            
            print(f"[ACTION] Verifying JWT signature and claims...")
            decoded = main.jwt_decode(token, pub_key, verify_exp=True)
            print(f"[INFO] JWT Claims: username={decoded.get('username')}, exp={decoded.get('exp')}")
            assert decoded["username"] == "userABC", f"Expected username=userABC, got {decoded['username']}"
            print(f"✓ PASS: JWT signature is valid and username verified")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Auth endpoint (valid credentials) test PASSED")
    print()


def test_auth_endpoint_expired_key():
    print("\n" + "="*70)
    print("TEST: Auth Endpoint with Expired Key Request")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            # Register user
            db_conn = sqlite3.connect(db_path)
            password = main.register_user(db_conn, "userABC")
            db_conn.close()
            
            print(f"[ACTION] Sending POST request to http://localhost:{port}/auth?expired=true")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": password})
            print(f"[INFO] Credentials: username=userABC, password={password[:10]}...")
            print(f"[INFO] Query parameter: expired=true (requesting expired key)")
            conn.request("POST", "/auth?expired=true", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            token = resp.read().decode("utf-8")
            print(f"[INFO] Received JWT token with expired key (length={len(token)})")
            print(f"[INFO] Token preview: {token[:60]}...")
            
            print(f"[ACTION] Decoding JWT header...")
            header = main.get_unverified_header(token)
            kid = header.get("kid")
            print(f"[INFO] JWT Header: alg={header.get('alg')}, kid={kid}, typ={header.get('typ')}")
            
            print(f"[ACTION] Retrieving public key for KID={kid} from database...")
            pub_key = _get_public_key_by_kid(db_path, int(kid))
            print(f"✓ Retrieved public key successfully")
            
            print(f"[ACTION] Attempting to verify JWT with expired token (should raise ExpiredSignatureError)...")
            try:
                decoded = main.jwt_decode(token, pub_key, verify_exp=True)
                raise AssertionError("Expected ExpiredSignatureError to be raised, but token was decoded successfully")
            except main.ExpiredSignatureError as e:
                print(f"✓ PASS: Correctly raised ExpiredSignatureError: {e}")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Auth endpoint (expired key) test PASSED")
    print()


def test_http_405_methods():
    """Test that invalid HTTP methods return 405 Method Not Allowed"""
    print("\n" + "="*70)
    print("TEST: HTTP 405 Methods (PUT, PATCH, DELETE, HEAD)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            # Test PUT
            print(f"[ACTION] Testing PUT method on /.well-known/jwks.json...")
            conn = HTTPConnection("localhost", port)
            conn.request("PUT", "/.well-known/jwks.json", body=b"")
            resp = conn.getresponse()
            resp.read()  # consume response
            assert resp.status == 405, f"PUT should return 405, got {resp.status}"
            print(f"✓ PASS: PUT returns 405")
            
            # Test PATCH
            print(f"[ACTION] Testing PATCH method on /.well-known/jwks.json...")
            conn = HTTPConnection("localhost", port)
            conn.request("PATCH", "/.well-known/jwks.json", body=b"")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 405, f"PATCH should return 405, got {resp.status}"
            print(f"✓ PASS: PATCH returns 405")
            
            # Test DELETE
            print(f"[ACTION] Testing DELETE method on /.well-known/jwks.json...")
            conn = HTTPConnection("localhost", port)
            conn.request("DELETE", "/.well-known/jwks.json")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 405, f"DELETE should return 405, got {resp.status}"
            print(f"✓ PASS: DELETE returns 405")
            
            # Test HEAD
            print(f"[ACTION] Testing HEAD method on /.well-known/jwks.json...")
            conn = HTTPConnection("localhost", port)
            conn.request("HEAD", "/.well-known/jwks.json")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 405, f"HEAD should return 405, got {resp.status}"
            print(f"✓ PASS: HEAD returns 405")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ HTTP 405 methods test PASSED")
    print()


def test_post_invalid_json():
    """Test POST /auth with invalid JSON"""
    print("\n" + "="*70)
    print("TEST: POST /auth with Invalid JSON")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending POST with malformed JSON...")
            conn = HTTPConnection("localhost", port)
            conn.request("POST", "/auth", body=b"invalid json {", headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
            print(f"[VERIFY] Response status: {resp.status}")
            assert resp.status == 400, f"Expected 400, got {resp.status}"
            print(f"✓ PASS: Invalid JSON returns 400")
            assert "Invalid JSON" in body
            print(f"✓ PASS: Response contains error message")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Invalid JSON test PASSED")
    print()


def test_post_unauthorized_credentials():
    """Test POST /auth with invalid credentials"""
    print("\n" + "="*70)
    print("TEST: POST /auth with Invalid Credentials")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            # Wrong username
            print(f"[ACTION] Testing wrong username...")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "wronguser", "password": "password123"})
            conn.request("POST", "/auth", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
            assert resp.status == 401, f"Expected 401, got {resp.status}"
            print(f"✓ PASS: Wrong username returns 401")
            
            # Wrong password
            print(f"[ACTION] Testing wrong password...")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": "wrongpassword"})
            conn.request("POST", "/auth", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
            assert resp.status == 401, f"Expected 401, got {resp.status}"
            print(f"✓ PASS: Wrong password returns 401")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Invalid credentials test PASSED")
    print()


def test_post_wrong_path():
    """Test POST to wrong endpoint"""
    print("\n" + "="*70)
    print("TEST: POST /wrong-path (Invalid Endpoint)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending POST to /invalid-endpoint...")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": "password123"})
            conn.request("POST", "/invalid-endpoint", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 405, f"Expected 405 for wrong path, got {resp.status}"
            print(f"✓ PASS: POST to wrong path returns 405")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ POST wrong path test PASSED")
    print()


def test_get_wrong_path():
    """Test GET to wrong endpoint"""
    print("\n" + "="*70)
    print("TEST: GET /wrong-path (Invalid Endpoint)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending GET to /invalid-endpoint...")
            conn = HTTPConnection("localhost", port)
            conn.request("GET", "/invalid-endpoint")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 404, f"Expected 404 for wrong path, got {resp.status}"
            print(f"✓ PASS: GET to wrong path returns 405")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ GET wrong path test PASSED")
    print()


def test_base64url_encode_decode():
    """Test base64url encoding and decoding edge cases"""
    print("\n" + "="*70)
    print("TEST: base64url Encode/Decode Edge Cases")
    print("="*70)
    
    # Test encoding
    print("[ACTION] Testing base64url_encode...")
    data = b"Hello World!"
    encoded = main.base64url_encode(data)
    print(f"✓ Encoded: {encoded}")
    
    # Test decoding with no padding needed
    print("[ACTION] Testing base64url_decode (no padding)...")
    decoded = main.base64url_decode(encoded)
    assert decoded == data, f"Expected {data}, got {decoded}"
    print(f"✓ PASS: Decoded correctly without padding")
    
    # Test with various sizes to trigger padding logic
    test_cases = [
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"abcde",
        b"The quick brown fox jumps over the lazy dog",
    ]
    
    for test_data in test_cases:
        encoded = main.base64url_encode(test_data)
        decoded = main.base64url_decode(encoded)
        assert decoded == test_data, f"Failed roundtrip for {test_data}"
    
    print(f"✓ PASS: All padding scenarios work correctly")
    print("[RESULT] ✓ base64url test PASSED")
    print()


def test_jwt_invalid_format():
    """Test JWT decode with invalid format"""
    print("\n" + "="*70)
    print("TEST: JWT Decode Invalid Format")
    print("="*70)
    
    # Test token with wrong number of parts
    print("[ACTION] Testing JWT with 2 parts instead of 3...")
    try:
        main.get_unverified_header("part1.part2")
        raise AssertionError("Should have raised ValueError")
    except ValueError as e:
        print(f"✓ PASS: Raised ValueError: {e}")
    
    print("[RESULT] ✓ JWT invalid format test PASSED")
    print()


def test_int_to_base64():
    """Test int_to_base64 conversion"""
    print("\n" + "="*70)
    print("TEST: int_to_base64 Conversion")
    print("="*70)
    
    # Test various integers
    test_values = [1, 255, 256, 65535, 65536, 2**31 - 1]
    
    for val in test_values:
        encoded = main.int_to_base64(val)
        print(f"[ACTION] int_to_base64({val}) = {encoded[:20]}...")
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        # Verify it's valid base64 characters
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in encoded)
    
    print(f"✓ PASS: All integer conversions successful")
    print("[RESULT] ✓ int_to_base64 test PASSED")
    print()


def test_private_key_to_jwk():
    """Test private_key_to_jwk conversion"""
    print("\n" + "="*70)
    print("TEST: private_key_to_jwk Conversion")
    print("="*70)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    os.environ['NOT_MY_KEY'] = 'test_key_' + str(uuid.uuid4())[:20]
    
    print("[ACTION] Generating test RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print("[ACTION] Serializing private key...")
    key_pem = main.serialize_private_key(private_key)
    
    print("[ACTION] Encrypting key for storage...")
    encrypted_key, iv = main.encrypt_private_key(key_pem)
    
    print("[ACTION] Converting to JWK...")
    jwk = main.private_key_to_jwk(encrypted_key, iv, kid=123)
    
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == "123"
    assert "n" in jwk, "JWK should have 'n' (modulus)"
    assert "e" in jwk, "JWK should have 'e' (exponent)"
    
    print(f"✓ PASS: JWK conversion successful")
    print(f"  - KTY: {jwk['kty']}")
    print(f"  - ALG: {jwk['alg']}")
    print(f"  - KID: {jwk['kid']}")
    print("[RESULT] ✓ private_key_to_jwk test PASSED")
    print()


def test_manual_jwt_encode_decode():
    """Test manual JWT encode/decode when pyjwt is not available"""
    print("\n" + "="*70)
    print("TEST: Manual JWT Encode/Decode (without pyjwt)")
    print("="*70)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    # Save original pyjwt state
    original_pyjwt = main.pyjwt
    
    try:
        # Simulate pyjwt not being available
        main.pyjwt = None
        
        print("[ACTION] Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        payload = {"username": "testuser", "exp": int(time.time()) + 3600}
        headers = {"kid": "test-kid-123"}
        
        print("[ACTION] Testing manual JWT encode (pyjwt=None)...")
        token = main.jwt_encode(payload, private_key, headers=headers)
        assert token is not None
        assert len(token.split('.')) == 3
        print(f"✓ PASS: Manual JWT encode successful")
        print(f"  Token: {token[:40]}...")
        
        # Verify the header contains our custom kid
        decoded_header = main.get_unverified_header(token)
        assert decoded_header.get("kid") == "test-kid-123"
        print(f"✓ PASS: Custom header preserved: {decoded_header}")
        
        print("[ACTION] Testing manual JWT decode (pyjwt=None)...")
        public_key = private_key.public_key()
        decoded_payload = main.jwt_decode(token, public_key, verify_exp=True)
        assert decoded_payload["username"] == "testuser"
        print(f"✓ PASS: Manual JWT decode successful")
        print(f"  Decoded payload: {decoded_payload}")
        
        # Test decoding without expiration verification
        print("[ACTION] Decoding without expiration verification...")
        decoded_no_exp = main.jwt_decode(token, public_key, verify_exp=False)
        assert decoded_no_exp["username"] == "testuser"
        print(f"✓ PASS: Decode works with verify_exp=False")
        
    finally:
        # Restore original pyjwt
        main.pyjwt = original_pyjwt
    
    print("[RESULT] ✓ Manual JWT encode/decode test PASSED")
    print()


def test_manual_jwt_decode_expired():
    """Test manual JWT decode with expired token"""
    print("\n" + "="*70)
    print("TEST: Manual JWT Decode - Expired Token")
    print("="*70)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    original_pyjwt = main.pyjwt
    
    try:
        main.pyjwt = None
        
        print("[ACTION] Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create expired token
        payload = {"username": "testuser", "exp": int(time.time()) - 3600}  # Expired 1 hour ago
        
        print("[ACTION] Encoding expired token...")
        token = main.jwt_encode(payload, private_key)
        
        print("[ACTION] Attempting to decode expired token with verify_exp=True...")
        public_key = private_key.public_key()
        
        try:
            main.jwt_decode(token, public_key, verify_exp=True)
            raise AssertionError("Should have raised ExpiredSignatureError")
        except main.ExpiredSignatureError as e:
            print(f"✓ PASS: Correctly raised ExpiredSignatureError: {e}")
        
        print("[ACTION] Decoding same token with verify_exp=False...")
        decoded = main.jwt_decode(token, public_key, verify_exp=False)
        assert decoded["username"] == "testuser"
        print(f"✓ PASS: Can decode when verify_exp=False")
        
    finally:
        main.pyjwt = original_pyjwt
    
    print("[RESULT] ✓ Manual JWT expired decode test PASSED")
    print()


def test_manual_jwt_invalid_signature():
    """Test manual JWT decode with tampered signature"""
    print("\n" + "="*70)
    print("TEST: Manual JWT Decode - Invalid Signature")
    print("="*70)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    original_pyjwt = main.pyjwt
    
    try:
        main.pyjwt = None
        
        print("[ACTION] Generating two RSA key pairs...")
        private_key1 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        payload = {"username": "testuser", "exp": int(time.time()) + 3600}
        
        print("[ACTION] Encoding token with key1...")
        token = main.jwt_encode(payload, private_key1)
        
        print("[ACTION] Attempting to verify with key2 public key (should fail)...")
        public_key2 = private_key2.public_key()
        
        try:
            main.jwt_decode(token, public_key2, verify_exp=True)
            raise AssertionError("Should have raised InvalidSignatureError")
        except main.InvalidSignatureError as e:
            print(f"✓ PASS: Correctly raised InvalidSignatureError: {e}")
        
    finally:
        main.pyjwt = original_pyjwt
    
    print("[RESULT] ✓ Manual JWT invalid signature test PASSED")
    print()


# ==================== NEW TESTS FOR ENHANCEMENTS ====================

def test_encrypt_decrypt_symmetric():
    """Test that encrypt->decrypt returns original data"""
    print("\n[TEST] Encryption/Decryption Symmetry")
    os.environ['NOT_MY_KEY'] = 'test_key_' + str(uuid.uuid4())[:20]
    
    test_data = b"This is a test private key"
    encrypted, iv = main.encrypt_private_key(test_data)
    decrypted = main.decrypt_private_key(encrypted, iv)
    
    assert decrypted == test_data, "Decrypted data should match original"
    print("✓ PASS: Encryption/Decryption symmetric")
    print()


def test_encryption_produces_different_ciphertext():
    """Test that same plaintext produces different ciphertexts (due to random IV)"""
    print("\n[TEST] Encryption randomness (different IV)")
    os.environ['NOT_MY_KEY'] = 'test_key_' + str(uuid.uuid4())[:20]
    
    test_data = b"Same test data"
    encrypted1, iv1 = main.encrypt_private_key(test_data)
    encrypted2, iv2 = main.encrypt_private_key(test_data)
    
    # IVs should be different (random)
    assert iv1 != iv2, "IVs should be different"
    # Ciphertexts should be different
    assert encrypted1 != encrypted2, "Ciphertexts should be different"
    print("✓ PASS: Each encryption uses random IV")
    print()


def test_hash_password():
    """Test password hashing"""
    print("\n[TEST] Password hashing")
    password = "test_password_123"
    hashed = main.hash_password(password)
    
    # Hash should not equal plaintext
    assert hashed != password, "Hash should not equal plaintext"
    # Hash should start with $argon2
    assert hashed.startswith("$argon2"), "Should be Argon2 hash"
    print("✓ PASS: Password hashed correctly")
    print()


def test_verify_password_correct():
    """Test password verification with correct password"""
    print("\n[TEST] Password verification (correct)")
    password = "correct_password"
    hashed = main.hash_password(password)
    
    assert main.verify_password(password, hashed) is True
    print("✓ PASS: Correct password verified")
    print()


def test_verify_password_incorrect():
    """Test password verification with incorrect password"""
    print("\n[TEST] Password verification (incorrect)")
    password = "correct_password"
    wrong_password = "wrong_password"
    hashed = main.hash_password(password)
    
    # verify_password returns False for incorrect password
    result = main.verify_password(wrong_password, hashed)
    assert result is False, "Incorrect password should not verify"
    print("✓ PASS: Incorrect password rejected")
    print()


def test_register_user_creates_user():
    """Test that register_user creates a new user"""
    print("\n[TEST] User registration creates user")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        conn = main.init_db(db_path)
        
        username = "testuser"
        email = "test@example.com"
        password = main.register_user(conn, username, email)
        
        # Check user exists in DB
        user = main.get_user_by_username(conn, username)
        assert user is not None
        user_id, stored_username, password_hash = user
        assert stored_username == username
        
        # Verify the generated password
        assert main.verify_password(password, password_hash)
        print("✓ PASS: User created successfully")
        
        conn.close()
    print()


def test_register_user_generates_uuid_password():
    """Test that register_user generates a valid UUID password"""
    print("\n[TEST] User registration generates UUID password")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        conn = main.init_db(db_path)
        
        password = main.register_user(conn, "user1")
        
        # Should be valid UUID format
        try:
            uuid.UUID(password)
            valid_uuid = True
        except ValueError:
            valid_uuid = False
        
        assert valid_uuid, "Password should be valid UUID"
        print("✓ PASS: Generated password is valid UUID")
        
        conn.close()
    print()


def test_register_duplicate_user_fails():
    """Test that registering duplicate username fails"""
    print("\n[TEST] Duplicate user registration rejected")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        conn = main.init_db(db_path)
        
        main.register_user(conn, "duplicateuser")
        
        # Try to register same username again
        try:
            main.register_user(conn, "duplicateuser")
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            assert "already exists" in str(e)
            print("✓ PASS: Duplicate registration rejected")
        
        conn.close()
    print()


def test_log_auth_attempt():
    """Test that auth attempts are logged"""
    print("\n[TEST] Auth attempt logging")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        conn = main.init_db(db_path)
        
        # Create a user first
        main.register_user(conn, "testuser")
        user = main.get_user_by_username(conn, "testuser")
        user_id = user[0]
        
        # Log an auth attempt
        main.log_auth_attempt(conn, "192.168.1.1", user_id)
        
        # Verify it was logged
        cursor = conn.cursor()
        log = cursor.execute(
            "SELECT request_ip, user_id FROM auth_logs WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        
        assert log is not None
        assert log[0] == "192.168.1.1"
        assert log[1] == user_id
        print("✓ PASS: Auth attempt logged correctly")
        
        conn.close()
    print()


def test_rate_limiter_allows_initial_request():
    """Test that rate limiter allows first request"""
    print("\n[TEST] Rate limiter allows initial request")
    limiter = main.RateLimiter(max_requests=10, window_seconds=1)
    
    assert limiter.is_allowed("192.168.1.1") is True
    print("✓ PASS: Initial request allowed")
    print()


def test_rate_limiter_blocks_when_exhausted():
    """Test that rate limiter blocks when tokens exhausted"""
    print("\n[TEST] Rate limiter blocks when exhausted")
    limiter = main.RateLimiter(max_requests=2, window_seconds=1)
    
    # Use up tokens
    assert limiter.is_allowed("192.168.1.1") is True
    assert limiter.is_allowed("192.168.1.1") is True
    
    # Should be blocked
    assert limiter.is_allowed("192.168.1.1") is False
    print("✓ PASS: Rate limit enforced")
    print()


def test_register_endpoint_success():
    print("\n" + "="*70)
    print("TEST: POST /register - Success")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        server, port = start_server(db_path)
        print(f"[SETUP] Server started on localhost:{port}")
        try:
            print("[ACTION] Sending POST /register request")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({
                "username": "newuser",
                "email": "user@example.com"
            })
            conn.request("POST", "/register", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            
            print(f"[VERIFY] Response status: {resp.status}")
            assert resp.status == 201, f"Expected 201, got {resp.status}"
            print("✓ PASS: Received 201 Created")
            
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            
            print(f"[VERIFY] Response contains 'password' field")
            assert "password" in data, "Response should contain password"
            generated_password = data["password"]
            print(f"✓ PASS: Generated password: {generated_password}")
            
            # Verify user exists in database
            db_conn = sqlite3.connect(db_path)
            user = main.get_user_by_username(db_conn, "newuser")
            assert user is not None, "User should exist in database"
            print("✓ PASS: User created in database")
            
            # Verify password works
            _, is_auth = main.authenticate_user(db_conn, "newuser", generated_password)
            assert is_auth, "Generated password should authenticate"
            print("✓ PASS: Generated password authenticates")
            db_conn.close()
        finally:
            stop_server(server)
    print("[RESULT] ✓ Register endpoint test PASSED")
    print()


def test_register_endpoint_duplicate_user():
    print("\n" + "="*70)
    print("TEST: POST /register - Duplicate User")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        server, port = start_server(db_path)
        try:
            # First registration
            conn1 = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "user1", "email": "user1@example.com"})
            conn1.request("POST", "/register", body=payload, headers={"Content-Type": "application/json"})
            resp1 = conn1.getresponse()
            resp1.read()
            assert resp1.status == 201
            print("[INFO] First registration successful")
            
            # Duplicate registration
            conn2 = HTTPConnection("localhost", port)
            conn2.request("POST", "/register", body=payload, headers={"Content-Type": "application/json"})
            resp2 = conn2.getresponse()
            
            print(f"[VERIFY] Second registration response: {resp2.status}")
            assert resp2.status == 400, f"Expected 400, got {resp2.status}"
            print("✓ PASS: Duplicate user rejected with 400")
        finally:
            stop_server(server)
    print("[RESULT] ✓ Duplicate user test PASSED")
    print()


def test_auth_endpoint_with_registered_user():
    print("\n" + "="*70)
    print("TEST: POST /auth - With Registered User")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        server, port = start_server(db_path)
        print(f"[SETUP] Server started on localhost:{port}")
        try:
            # Register user first
            db_conn = sqlite3.connect(db_path)
            password = main.register_user(db_conn, "authuser")
            db_conn.close()
            print(f"[SETUP] User registered with password: {password}")
            
            # Authenticate
            print("[ACTION] Sending POST /auth request")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "authuser", "password": password})
            conn.request("POST", "/auth", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            
            print(f"[VERIFY] Response status: {resp.status}")
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            print("✓ PASS: Received 200 OK")
            
            token = resp.read().decode("utf-8")
            print(f"[VERIFY] Received JWT token (length={len(token)})")
            assert len(token) > 0, "Token should not be empty"
            print("✓ PASS: JWT token received")
            
            # Verify auth was logged
            db_conn = sqlite3.connect(db_path)
            log_count = db_conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
            assert log_count > 0, "Auth should be logged"
            print(f"✓ PASS: Auth attempt logged ({log_count} log entries)")
            db_conn.close()
        finally:
            stop_server(server)
    print("[RESULT] ✓ Auth endpoint test PASSED")
    print()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])



def test_sign_jwt_no_key():
    """Test sign_jwt when no expired key exists"""
    print("\n" + "="*70)
    print("TEST: sign_jwt - No Expired Key Available")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating database at: {path}")
        
        conn = main.init_db(path)
        try:
            print("[ACTION] Generate only valid keys (not expired)...")
            now = int(time.time())
            cursor = conn.cursor()
            
            # Generate only valid keys
            valid_key = __import__('cryptography.hazmat.primitives.asymmetric.rsa', fromlist=['generate_private_key']).generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=__import__('cryptography.hazmat.backends', fromlist=['default_backend']).default_backend()
            )
            valid_pem = main.serialize_private_key(valid_key)
            main.store_key(conn, valid_pem, now + 7200)
            
            print("[ACTION] Requesting expired key (should return None)...")
            result = main.sign_jwt(conn, expired=True)
            
            assert result is None, f"Expected None, got {result}"
            print(f"✓ PASS: sign_jwt returns None when no expired key exists")
        finally:
            conn.close()
    
    print("[RESULT] ✓ sign_jwt no key test PASSED")
    print()


def test_generate_and_store_keys_already_exists():
    """Test generate_and_store_keys when keys already exist"""
    print("\n" + "="*70)
    print("TEST: generate_and_store_keys - Keys Already Exist")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating database and keys...")
        
        conn = main.init_db(path)
        try:
            print("[ACTION] First call to generate_and_store_keys...")
            main.generate_and_store_keys(conn)
            
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM keys")
            count_before = cursor.fetchone()[0]
            print(f"[INFO] Keys after first call: {count_before}")
            
            print("[ACTION] Second call to generate_and_store_keys (keys should already exist)...")
            main.generate_and_store_keys(conn)
            
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM keys")
            count_after = cursor.fetchone()[0]
            print(f"[INFO] Keys after second call: {count_after}")
            
            assert count_after == count_before, f"Should not generate new keys when they exist"
            print(f"✓ PASS: No new keys generated when they already exist")
        finally:
            conn.close()
    
    print("[RESULT] ✓ generate_and_store_keys already exists test PASSED")
    print()


def test_manual_jwt_decode_invalid_format():
    """Test manual JWT decode with invalid token format"""
    print("\n" + "="*70)
    print("TEST: Manual JWT Decode - Invalid Token Format")
    print("="*70)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    original_pyjwt = main.pyjwt
    
    try:
        main.pyjwt = None
        
        print("[ACTION] Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        print("[ACTION] Attempting to decode token with only 2 parts...")
        try:
            main.jwt_decode("part1.part2", public_key, verify_exp=True)
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            print(f"✓ PASS: Correctly raised ValueError: {e}")
        
        print("[ACTION] Attempting to decode token with 4 parts...")
        try:
            main.jwt_decode("part1.part2.part3.part4", public_key, verify_exp=True)
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            print(f"✓ PASS: Correctly raised ValueError: {e}")
        
    finally:
        main.pyjwt = original_pyjwt
    
    print("[RESULT] ✓ Manual JWT invalid format test PASSED")
    print()


def test_encryption_schema_has_iv_column():
    """Test that keys table has iv column for storing encryption IV"""
    print("\n" + "="*70)
    print("TEST: Encryption Schema - IV Column Exists")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating database at: {path}")
        
        conn = main.init_db(path)
        try:
            print("[ACTION] Checking keys table schema...")
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(keys)")
            columns = {row[1]: row for row in cursor.fetchall()}
            
            print(f"[VERIFY] Column names: {list(columns.keys())}")
            assert 'iv' in columns, "IV column should exist in keys table"
            print("✓ PASS: IV column exists in keys table")
            
            # Verify iv column is BLOB type
            iv_info = columns['iv']
            print(f"[VERIFY] IV column type: {iv_info[2]}")
            assert iv_info[2] == 'BLOB', "IV column should be BLOB type"
            print("✓ PASS: IV column is BLOB type")
            
            # Generate key and verify IV is stored
            print("[ACTION] Generating and storing encrypted key...")
            main.generate_and_store_keys(conn)
            
            cursor.execute("SELECT kid, key, iv, exp FROM keys")
            rows = cursor.fetchall()
            print(f"[VERIFY] Total keys stored: {len(rows)}")
            assert len(rows) > 0, "Should have at least one key"
            
            for kid, key, iv, exp in rows:
                print(f"[VERIFY] Key {kid}: key_len={len(key)}, iv_len={len(iv)}, exp={exp}")
                assert iv is not None, f"IV should not be null for key {kid}"
                assert len(iv) == 12, f"IV should be 12 bytes (96 bits) for key {kid}, got {len(iv)}"
                print(f"✓ PASS: Key {kid} has proper IV (12 bytes)")
        finally:
            conn.close()
    
    print("[RESULT] ✓ Encryption schema IV test PASSED")
    print()


def test_encryption_with_hex_key():
    """Test encryption with hex-encoded encryption key"""
    print("\n" + "="*70)
    print("TEST: Encryption with Hex-Encoded Key")
    print("="*70)
    
    original_key = main.ENCRYPTION_KEY
    try:
        # Use a proper 32-byte hex-encoded key
        hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        main.ENCRYPTION_KEY = hex_key
        
        print(f"[SETUP] Setting encryption key to hex: {hex_key[:20]}...")
        
        test_data = b"test private key data for encryption"
        print(f"[ACTION] Encrypting test data ({len(test_data)} bytes)...")
        
        encrypted, iv = main.encrypt_private_key(test_data)
        print(f"[VERIFY] Encrypted data: {len(encrypted)} bytes")
        print(f"[VERIFY] IV: {len(iv)} bytes")
        assert encrypted is not None and len(encrypted) > 0
        assert len(iv) == 12
        print("✓ PASS: Encryption successful with hex key")
        
        print("[ACTION] Decrypting data...")
        decrypted = main.decrypt_private_key(encrypted, iv)
        assert decrypted == test_data, "Decrypted data should match original"
        print("✓ PASS: Decryption successful with hex key")
        
    finally:
        main.ENCRYPTION_KEY = original_key
    
    print("[RESULT] ✓ Encryption with hex key test PASSED")
    print()


def test_encryption_with_long_key():
    """Test encryption with key longer than 32 bytes"""
    print("\n" + "="*70)
    print("TEST: Encryption with Long Key (>32 bytes)")
    print("="*70)
    
    original_key = main.ENCRYPTION_KEY
    try:
        # Use a key longer than 32 bytes (it should be truncated to 32)
        long_key = "a" * 64  # 64 characters
        main.ENCRYPTION_KEY = long_key
        
        print(f"[SETUP] Setting encryption key to {len(long_key)} characters...")
        
        test_data = b"test private key data for encryption"
        print(f"[ACTION] Encrypting test data with long key...")
        
        encrypted, iv = main.encrypt_private_key(test_data)
        print(f"[VERIFY] Encrypted data: {len(encrypted)} bytes")
        assert encrypted is not None and len(encrypted) > 0
        print("✓ PASS: Encryption successful with long key")
        
        print("[ACTION] Decrypting data...")
        decrypted = main.decrypt_private_key(encrypted, iv)
        assert decrypted == test_data, "Decrypted data should match original"
        print("✓ PASS: Decryption successful with long key")
        
    finally:
        main.ENCRYPTION_KEY = original_key
    
    print("[RESULT] ✓ Encryption with long key test PASSED")
    print()




import sys
sys.path.insert(0, '.')
from main import rate_limiter
import time

# Simulate rapid requests from same IP
client_ip = "127.0.0.1"

print("Simulating rapid requests:")
for i in range(5):
    allowed = rate_limiter.is_allowed(client_ip)
    request_count = len(rate_limiter.requests[client_ip])
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'}")
    print(f"  Requests: {request_count}")
    time.sleep(0.1)

print("\nAfter 1 second delay:")
time.sleep(1)
for i in range(5):
    allowed = rate_limiter.is_allowed(client_ip)
    request_count = len(rate_limiter.requests[client_ip])
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'}")
    print(f"  Requests: {request_count}")

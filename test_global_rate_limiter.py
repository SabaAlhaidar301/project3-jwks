#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from main import rate_limiter
import time

print("Testing global rate limiter:")
client_ip = "127.0.0.1"
for i in range(5):
    allowed = rate_limiter.is_allowed(client_ip)
    request_count = len(rate_limiter.requests[client_ip])
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'} (requests={request_count})")
    time.sleep(0.05)

print("\nAfter 1.1 second delay:")
time.sleep(1.1)
for i in range(3):
    allowed = rate_limiter.is_allowed(client_ip)
    request_count = len(rate_limiter.requests[client_ip])
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'} (requests={request_count})")

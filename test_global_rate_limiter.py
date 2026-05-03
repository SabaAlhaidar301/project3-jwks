#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from main import rate_limiter
import time

print("Testing global rate limiter:")
for i in range(5):
    allowed = rate_limiter.is_allowed()
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'} (tokens={rate_limiter.tokens:.3f})")
    time.sleep(0.05)

print("\nAfter 1.1 second delay:")
time.sleep(1.1)
for i in range(3):
    allowed = rate_limiter.is_allowed()
    print(f"Request {i+1}: {'ALLOWED' if allowed else 'RATE LIMITED'} (tokens={rate_limiter.tokens:.3f})")

#!/usr/bin/env python3
"""Quick test to see what login returns"""
import requests
import json

BASE_URL = "http://localhost:8888/api/v1"
CREDENTIALS = {
    "email": "bob@acme-corp.com",
    "password": "UserPass123!"
}

session = requests.Session()
response = session.post(f"{BASE_URL}/auth/login", json=CREDENTIALS)

print(f"Status: {response.status_code}")
print(f"Response:")
print(json.dumps(response.json(), indent=2))

if response.status_code == 200:
    data = response.json()["data"]
    if data.get("requires_totp"):
        print("\n⚠️  TOTP IS REQUIRED")
    elif data.get("token"):
        print(f"\n✅ LOGIN SUCCESS - Token: {data['token'][:30]}...")
        
        # Check TOTP status
        status_response = session.get(
            f"{BASE_URL}/auth/totp/status",
            headers={"Authorization": f"Bearer {data['token']}"}
        )
        print(f"\nTOTP Status:")
        print(json.dumps(status_response.json(), indent=2))

# TOTP End-to-End Test Proposal

## Test Objective
Test ALL aspects of TOTP functionality regardless of current state (TOTP enabled or disabled).

## Test Flow

### Scenario A: TOTP Currently Enabled (Bob already enrolled)

1. **Login** with email/password
   - Response: `requires_totp: true`
   
2. **Get Secret from DB** (or use environment variable)
   - Since secret is encrypted/hashed in DB, we need to either:
     - Store it in environment/file from previous enrollment, OR
     - User provides it as input, OR  
     - Use backup code from previous enrollment
   
3. **Generate TOTP Code** using stored secret/backup code
   
4. **Verify TOTP** to complete login
   - Endpoint: `/auth/totp/verify`
   - Get auth_token
   
5. **Check TOTP Status**
   - Endpoint: `/auth/totp/status`
   - Confirm: `totp_enabled: true`
   
6. **Disable TOTP**
   - Endpoint: `/auth/totp/disable`
   - Provide password
   
7. **Logout**
   
8. **Continue to Scenario B steps 2-14**

### Scenario B: TOTP Currently Disabled (or after completing Scenario A)

1. **Login** with email/password
   - Response: `token` (no TOTP required)
   
2. **Check TOTP Status**
   - Endpoint: `/auth/totp/status`
   - Confirm: `totp_enabled: false`
   
3. **Enroll in TOTP**
   - Endpoint: `/auth/totp/enroll`
   - Store: secret, backup_codes, provisioning_uri, qr_code
   
4. **Generate TOTP Code** from new secret
   - Use timezone-aware UTC
   
5. **Verify Enrollment**
   - Endpoint: `/auth/totp/verify-enrollment`
   - Provide generated code
   
6. **Check TOTP Status Again**
   - Confirm: `totp_enabled: true`
   - Confirm: `backup_codes_remaining: 10`
   - Confirm: `verified_at` is set
   
7. **Logout**
   
8. **Login** with email/password
   - Response: `requires_totp: true`
   
9. **Generate TOTP Code** from stored secret
   
10. **Verify TOTP** to complete login
    - Endpoint: `/auth/totp/verify`
    - Get auth_token
    
11. **Confirm Logged In**
    - Endpoint: `/auth/me`
    - Verify user data returned
    
12. **Test Backup Code** (new login)
    - Logout
    - Login with email/password
    - Use backup code instead of TOTP
    - Endpoint: `/auth/totp/verify` with `is_backup_code: true`
    
13. **Check Backup Codes Remaining**
    - Should be 9 (one consumed)
    
14. **Regenerate Backup Codes**
    - Endpoint: `/auth/totp/regenerate-backup-codes`
    - Provide password
    - Get new set of 10 codes

## Implementation Strategy

### Secret Persistence Between Test Runs

**Option 1: Environment Variable** (Recommended)
```python
import os

# Save secret after first successful enrollment
SECRET_FILE = ".totp_test_secret"

if os.path.exists(SECRET_FILE):
    with open(SECRET_FILE) as f:
        data = json.load(f)
        known_secret = data.get("secret")
        known_backup_codes = data.get("backup_codes", [])
else:
    known_secret = None
    known_backup_codes = []

# After enrollment, save for next run
with open(SECRET_FILE, 'w') as f:
    json.dump({
        "secret": new_secret,
        "backup_codes": new_backup_codes  
    }, f)
```

**Option 2: Test Database State**
- Include SQL query to fetch secret from DB (if stored in plain text for testing)
- Or decrypt if encrypted

**Option 3: Manual Input**
- Prompt user for secret/backup code if TOTP already enabled
- Less automated but more flexible

## Expected Assertions

1. ✅ Login without TOTP works when disabled
2. ✅ Enrollment generates secret, QR code, backup codes
3. ✅ Enrollment verification accepts valid TOTP code
4. ✅ TOTP status shows enabled after verification
5. ✅ Login requires TOTP when enabled
6. ✅ TOTP verification works during login
7. ✅ Backup code works for authentication
8. ✅ Backup codes decrement when used
9. ✅ Backup code regeneration works  
10. ✅ TOTP disable works with correct password
11. ✅ Login works without TOTP after disabling

## Test Data Management

Store in `.totp_test_data.json` (gitignored):
```json
{
  "user": "bob@acme-corp.com",
  "secret": "BWAQAP55...",
  "backup_codes": ["code1", "code2", ...],
  "enrollment_date": "2026-01-14T03:12:00Z",
  "last_test_run": "2026-01-14T03:15:00Z"
}
```

## Error Handling

- Connection errors → clear message about server not running
- 401 errors → check if token/credentials are correct
- TOTP code failures → check time synchronization
- Backup code failures → check if already used

## Success Criteria

Test passes when:
1. All 14 steps complete without errors
2. All assertions pass
3. Test can run multiple times (idempotent)
4. Works from both initial states (TOTP enabled/disabled)

---

**Please review this proposal. Once approved, I'll implement it.**

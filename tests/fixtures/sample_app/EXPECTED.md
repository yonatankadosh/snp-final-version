# Expected results (GDPR active)

Violations:
- `app.py` `OWNER = {...}`: GDPR-001 (real-looking name and email)
- `app.py` `logger.info(f"created {user}")`: GDPR-002 (whole user object logged)
- `client.js` `console.log(user.email)`: GDPR-002

Not violations (regex false positives or compliant):
- `SUPPORT_EMAIL` (example.invalid placeholder)
- `RELEASED_AT`, `TIMEOUT_MS` (not phone numbers)
- `logger.info("email_enabled=%s", ...)` (boolean flag)
- `logger.info("created user_id=%s", user.id)` and `console.log("login ok", user.id)` (pseudonymous ID)
- `print("server address", "0.0.0.0")` (not personal)

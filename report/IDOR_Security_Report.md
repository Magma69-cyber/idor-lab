# Security Assessment Report
## Insecure Direct Object Reference (IDOR) — Lab Environment

---

| Field            | Detail                                  |
|------------------|-----------------------------------------|
| **Report Date**  | June 2026                               |
| **Author**       | Trupti Ranjan (CSCD Batch 2024–28)     |
| **Target**       | IDOR Lab — Flask Application            |
| **Scope**        | `/profile/<user_id>/update` endpoint    |
| **Environment**  | Local / Docker (Controlled Lab)         |
| **Severity**     | High (CVSS 3.1: ~8.1)                  |
| **Status**       | Remediated ✅                           |

---

## 1. Executive Summary

A critical Insecure Direct Object Reference (IDOR) vulnerability was identified and demonstrated in the vulnerable version of this lab application. The affected endpoint allowed any authenticated user to modify the profile data of **any other user** simply by altering the numeric `user_id` value in the HTTP request URL.

This vulnerability maps to **OWASP Top 10 A01:2021 — Broken Access Control**.

---

## 2. Vulnerability Details

### 2.1 Vulnerability Type
- **Name:** Insecure Direct Object Reference (IDOR)
- **Category:** Broken Access Control (OWASP A01:2021)
- **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
- **Severity:** High

### 2.2 Affected Endpoint
```
POST /profile/<user_id>/update
```

### 2.3 Root Cause
The endpoint accepted a user-controlled `user_id` path parameter and directly used it to look up and modify database records **without verifying** whether the authenticated session user owned the referenced object.

**Vulnerable Code (Python/Flask):**
```python
@app.route('/profile/<int:user_id>/update', methods=['POST'])
def update_profile(user_id):
    user = User.query.get(user_id)       # ← Direct lookup using attacker-controlled value
    user.username = request.form['username']
    db.session.commit()
    return "Updated"
    # ❌  No check: is session["user_id"] == user_id ?
```

---

## 3. Attack Scenario

### Prerequisites
- Attacker holds a valid session (any registered account)
- Target user ID is known (often discoverable via enumeration or profile URLs)

### Steps to Reproduce

**Step 1:** Log in as `alice` (User ID: 1).

**Step 2:** Navigate to Alice's profile and capture an update request in Burp Suite:
```http
POST /profile/1/update HTTP/1.1
Host: localhost:5000
Cookie: session=<alice_session_token>

username=alice&email=alice@lab.com&bio=My+normal+bio
```

**Step 3:** Modify the URL to target Bob (User ID: 2):
```http
POST /profile/2/update HTTP/1.1
Host: localhost:5000
Cookie: session=<alice_session_token>

username=hacked_by_alice&email=attacker@evil.com&bio=COMPROMISED
```

**Result:** Bob's profile is overwritten. The server responds with `HTTP 200 OK`.

### Impact
- Unauthorized modification of other users' profiles
- Potential account takeover (changing email, username)
- Data integrity violation
- In a real application: PII exposure, privilege escalation

---

## 4. Evidence

| Screenshot | Description |
|------------|-------------|
| `screenshots/01_legitimate_request.png` | Normal POST to `/profile/1/update` from Alice's session |
| `screenshots/02_idor_attack.png` | Modified POST to `/profile/2/update` — server returns 200 OK |
| `screenshots/03_bobs_profile_modified.png` | Bob's profile showing Alice's injected data |
| `screenshots/04_fixed_403.png` | Fixed version returns `403 Forbidden` on the same attempt |

---

## 5. Remediation

### 5.1 Fix Applied
Added an **ownership validation check** before processing any update:

**Fixed Code (Python/Flask):**
```python
@app.route('/profile/<int:user_id>/update', methods=['POST'])
@login_required
def update_profile(user_id):
    # ✅  Authorization check — session owner must match requested resource
    if session["user_id"] != user_id:
        return jsonify({"error": "403 Forbidden", "message": "Unauthorized"}), 403

    user = User.query.get(user_id)
    user.username = request.form.get('username', user.username)
    db.session.commit()
    return jsonify({"status": "updated"}), 200
```

### 5.2 Result After Fix
Repeating Step 3 from the attack scenario now returns:
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": "403 Forbidden", "message": "You are not authorized to modify this resource."}
```

### 5.3 General Recommendations

| Recommendation | Description |
|----------------|-------------|
| **Always validate ownership** | Never trust client-supplied object references. Verify the authenticated user owns the resource server-side. |
| **Use indirect references** | Map internal IDs to randomized tokens (UUIDs) per session. |
| **Enforce authorization at every layer** | Don't rely solely on UI hiding — enforce on the API. |
| **Log access violations** | 403 responses to sensitive endpoints should trigger alerts. |
| **Rate limit enumeration** | Limit requests per session to prevent ID enumeration attacks. |

---

## 6. CVSS 3.1 Score Breakdown

| Metric | Value |
|--------|-------|
| Attack Vector | Network (N) |
| Attack Complexity | Low (L) |
| Privileges Required | Low (L) |
| User Interaction | None (N) |
| Scope | Unchanged (U) |
| Confidentiality | Low (L) |
| Integrity | **High (H)** |
| Availability | None (N) |
| **Base Score** | **~7.1 (High)** |

---

## 7. References

- [OWASP Top 10 A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PortSwigger — IDOR Academy](https://portswigger.net/web-security/access-control/idor)

---

*This report was produced in a controlled, self-built lab environment for educational purposes only.*

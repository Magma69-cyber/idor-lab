# 🔓 IDOR Lab — Broken Access Control (OWASP A01:2021)

> A deliberately vulnerable Flask web application built to demonstrate, exploit, and remediate **Insecure Direct Object Reference (IDOR)** vulnerabilities — for hands-on security learning and portfolio documentation.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-A01%3A2021-red?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker)
![Lab](https://img.shields.io/badge/Type-Vulnerable%20Lab-orange?style=flat-square)

---

## 📌 What Is IDOR?

**Insecure Direct Object Reference (IDOR)** occurs when an application exposes internal object references (like database IDs) and fails to verify whether the requesting user is authorized to access or modify the referenced object.

```
Legitimate:  POST /profile/1/update  ← Alice updates her own profile
Attack:      POST /profile/2/update  ← Alice modifies Bob's profile (same session cookie)
```

This maps to **OWASP Top 10 A01:2021 — Broken Access Control**.

---

## 🏗️ Project Structure

```
idor-lab/
│
├── vulnerable-version/         ← App WITHOUT the authorization check (exploitable)
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── templates/
│       ├── login.html
│       ├── profile.html
│       └── users.html
│
├── fixed-version/              ← App WITH the authorization check (secure)
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── templates/
│       ├── login.html
│       ├── profile.html
│       └── users.html
│
├── screenshots/                ← Add your Burp Suite screenshots here
│   ├── 01_legitimate_request.png
│   ├── 02_idor_attack.png
│   ├── 03_profile_modified.png
│   └── 04_fixed_403.png
│
├── report/
│   └── IDOR_Security_Report.md ← Full VAPT-style security report
│
├── docker-compose.yml
└── README.md
```

---

## 🚀 Quick Start

### Option A — Run Locally (Python)

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/idor-lab.git
cd idor-lab

# Vulnerable version (port 5000)
cd vulnerable-version
pip install -r requirements.txt
python app.py

# Fixed version (port 5001) — open a second terminal
cd ../fixed-version
pip install -r requirements.txt
python app.py
```

### Option B — Docker Compose (Both Versions Simultaneously)

```bash
git clone https://github.com/YOUR_USERNAME/idor-lab.git
cd idor-lab
docker-compose up --build
```

| Version | URL |
|---------|-----|
| 🚨 Vulnerable | http://localhost:5000 |
| ✅ Fixed | http://localhost:5001 |

---

## 🔑 Lab Accounts

| Username | Password | User ID |
|----------|----------|---------|
| alice | alice123 | 1 |
| bob | bob123 | 2 |
| charlie | charlie123 | 3 |

---

## 🎯 Attack Walkthrough

### 1. Set Up Burp Suite Proxy
- Open Burp Suite → Proxy → Intercept ON
- Configure browser to proxy through `127.0.0.1:8080`

### 2. Log in as Alice
Navigate to `http://localhost:5000` and log in with `alice / alice123`.

### 3. Capture the Update Request
Update Alice's profile normally. In Burp, you'll see:
```http
POST /profile/1/update HTTP/1.1
Host: localhost:5000
Cookie: session=<alice_token>

username=alice&email=alice@lab.com&bio=My+bio
```

### 4. Tamper the User ID (IDOR Attack)
Send to Repeater → Change `/profile/1/` to `/profile/2/`:
```http
POST /profile/2/update HTTP/1.1
Host: localhost:5000
Cookie: session=<alice_token>

username=HACKED&email=attacker@evil.com&bio=Bob+was+here
```

### 5. Observe Result
**Vulnerable version:** `HTTP 200 OK` — Bob's data is overwritten ✅

**Fixed version:** `HTTP 403 Forbidden` — Request blocked ✅

---

## 🔐 The Fix — One Line That Matters

```python
# ❌ Vulnerable — no ownership check
def update_profile(user_id):
    user = User.query.get(user_id)
    user.username = request.form['username']
    db.session.commit()

# ✅ Fixed — ownership validated
def update_profile(user_id):
    if session["user_id"] != user_id:          # ← THIS IS THE FIX
        return jsonify({"error": "403 Forbidden"}), 403
    user = User.query.get(user_id)
    user.username = request.form['username']
    db.session.commit()
```

---

## 📋 Security Report

A full VAPT-style security report is available in [`report/IDOR_Security_Report.md`](./report/IDOR_Security_Report.md), covering:
- Vulnerability details and root cause
- Step-by-step attack reproduction
- CVSS 3.1 scoring
- Remediation applied
- General security recommendations

---

## 🧠 Key Learning Outcomes

- Understand how IDOR arises from missing authorization checks
- Use Burp Suite to intercept and tamper HTTP requests
- Demonstrate attack impact (profile hijack, data manipulation)
- Apply the correct server-side fix and verify it blocks the attack
- Write a structured VAPT security report

---

## ⚠️ Disclaimer

This lab is **intentionally vulnerable** and is designed exclusively for educational purposes in **controlled, local environments**. Do not deploy the vulnerable version to any public or production server. The techniques demonstrated here should only be practiced against systems you own or have explicit written permission to test.

---

## 🔗 References

- [OWASP Top 10 A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Web Security Academy — IDOR](https://portswigger.net/web-security/access-control/idor)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

---

*Built by Trupti Ranjan · Sri Sri University · CSCD Batch 2024–28*

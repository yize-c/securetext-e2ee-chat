# SecureText: End-to-End Encrypted Command-Line Chat

[![CI](https://github.com/yize-c/securetext-e2ee-chat/actions/workflows/ci.yml/badge.svg)](https://github.com/yize-c/securetext-e2ee-chat/actions/workflows/ci.yml)

SecureText is a client–server chat that runs in the terminal over TCP sockets.
I took an intentionally insecure starter version and hardened it step by step:
first password storage and login, then multi-factor authentication and access
control, and finally end-to-end encryption, so that the server can route
messages but never read them.

## Features

**End-to-end encryption**
- ECDH key exchange on the P-256 curve; each pair of users derives its own session key
- HKDF-SHA256 turns the shared secret into a 256-bit AES key
- AES-256-GCM encrypts every message, with a fresh nonce each time, and detects tampering
- The server only relays public keys and ciphertext; it never sees private keys, session keys, or plaintext

**Authentication**
- Passwords stored as salted PBKDF2-HMAC-SHA256 hashes (100,000 iterations)
- TOTP two-factor authentication (Google Authenticator compatible), with a QR code at sign-up
- GitHub OAuth 2.0 login with a random `state` value to prevent CSRF
- HMAC challenge-response step before the password and TOTP check

**Access control and monitoring**
- Role-based access control: admin-only commands are blocked for regular users
- Account lockout after 3 failed login attempts
- Audit log of logins, failures, and access-control decisions (`auth.log`)

**Session management**
- Sessions expire after 30 minutes of inactivity, with a warning 5 minutes before
- A background monitor thread checks idle users; shared state is protected with a thread lock
- Session keys are cleared from memory on logout or expiry

**Networking**
- Newline-delimited JSON framing over TCP, so messages are never split or merged

## How It Works

```
Alice (client)                 Server                  Bob (client)
   | -- ECDH public key -----> | -- relay public key --> |
   | <-- relay public key ---- | <-- ECDH public key --- |
   |  both sides: ECDH -> HKDF-SHA256 -> same AES-256 session key
   | -- AES-GCM ciphertext --> | -- relay ciphertext --> |  decrypt + verify
```

## Getting Started

Requires Python 3.9 or later (or Docker, see below).

```bash
pip install -r requirements.txt

# Use the same random value in every terminal (server and clients)
export SECURETEXT_CHALLENGE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Start the server in one terminal:

```bash
python3 securetext.py server
```

Start a client in each additional terminal (for example, one for Alice and one for Bob):

```bash
python3 securetext.py
```

Then create accounts, scan the QR code with an authenticator app, log in, choose
**Start Secure (E2EE) Session with a User**, and send messages.

### Optional: GitHub login

Create a GitHub OAuth app with the callback URL `http://localhost:8080/oauth/callback`, then set:

```bash
export GITHUB_CLIENT_ID=your_client_id
export GITHUB_CLIENT_SECRET=your_client_secret
```

Secrets are only read from environment variables and are never stored in the code.
The local user database (`users.json`) and `auth.log` are excluded by `.gitignore`.

### Run with Docker Compose

```bash
cp .env.example .env          # then put a random value in SECURETEXT_CHALLENGE_KEY
docker compose up -d server   # start the server
docker compose run --rm client   # run this in two terminals for two users
```

The container runs as a non-root user. GitHub login opens a browser, so use it when running locally rather than in Docker.

## Testing and CI

Every push runs three GitHub Actions jobs:

| Job | Tool | What it checks |
|---|---|---|
| Tests | **pytest** | 22 unit and integration tests |
| Static analysis | **Bandit** | Insecure Python patterns (SAST) |
| Dependency scan | [Dependency Security Analyzer](https://github.com/yize-c/dependency-security-analyzer) | Known CVEs in `requirements.txt`; the build fails on any high-risk package |

The tests cover:
- ECDH: both clients derive the same 256-bit key, and different pairs get different keys
- AES-GCM: round trips, a fresh nonce per message, and rejection of tampered ciphertext
- Authentication: salted hashes, wrong password or TOTP, and single-use challenge responses
- Integration: two real clients talk through a running server, and the plaintext never shows up in the server's output or logs

Run them locally:

```bash
pip install pytest bandit
pytest -v
bandit -r securetext.py
```

## Tech Stack

Python, `socket`, `threading`, `cryptography` (ECDH, HKDF, AES-GCM), `pyotp`, `qrcode`, `requests`, pytest, Bandit, GitHub Actions, Docker

## Credits

Built on the SecureText starter code by Ardeshir Shojaeinasab (MIT License).
All security features listed above were implemented by Yize Chen.

"""Password hashing, TOTP 2FA, and HMAC challenge-response on the server."""
import hashlib
import hmac

import pyotp
import pytest

import securetext as st


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep users.json and auth.log out of the repo
    srv = st.SecureTextServer()
    ok, _ = srv.create_account("alice", "correct horse")
    assert ok
    return srv


def totp_now(server, username):
    return pyotp.TOTP(server.users[username]["totp_secret"]).now()


def test_password_is_stored_salted_and_hashed(server):
    record = server.users["alice"]
    assert "correct horse" not in record["password"]
    assert len(bytes.fromhex(record["salt"])) == 16


def test_same_password_gets_different_hashes(server):
    server.create_account("bob", "correct horse")
    assert server.users["alice"]["password"] != server.users["bob"]["password"]


def test_duplicate_username_is_rejected(server):
    ok, msg = server.create_account("alice", "anything")
    assert not ok and "exists" in msg


def test_login_succeeds_with_password_and_totp(server):
    ok, _ = server.authenticate("alice", "correct horse", totp_now(server, "alice"))
    assert ok


def test_wrong_password_is_rejected(server):
    ok, msg = server.authenticate("alice", "wrong", totp_now(server, "alice"))
    assert not ok and "password" in msg.lower()


def test_wrong_totp_is_rejected(server):
    ok, msg = server.authenticate("alice", "correct horse", "000000")
    assert not ok and "totp" in msg.lower()


def test_challenge_response_accepts_correct_hmac_once(server):
    server.challenges["alice"] = "abc123"
    good = hmac.new(st.CHALLENGE_KEY, b"abc123", hashlib.sha256).hexdigest()
    assert server.verify_challenge("alice", good)
    assert not server.verify_challenge("alice", good)  # single use: replay fails


def test_challenge_response_rejects_wrong_hmac(server):
    server.challenges["alice"] = "abc123"
    assert not server.verify_challenge("alice", "0" * 64)

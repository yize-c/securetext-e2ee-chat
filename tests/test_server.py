"""Integration test: two real clients talk through a running server over TCP,
and the server only ever sees ciphertext."""
import hashlib
import hmac
import socket
import threading
import time

import pyotp
import pytest

import securetext as st


def free_port():
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    port = free_port()
    srv = st.SecureTextServer(port=port)
    threading.Thread(target=srv.start_server, daemon=True).start()
    for _ in range(50):  # wait until the server is listening
        try:
            socket.create_connection(("localhost", port), timeout=0.1).close()
            break
        except OSError:
            time.sleep(0.05)
    return srv, port


class RawClient:
    def __init__(self, port):
        self.sock = socket.create_connection(("localhost", port), timeout=5)
        self.reader = st.JsonFrameReader(self.sock)

    def call(self, msg):
        st.send_json(self.sock, msg)
        return self.reader.read_message()

    def login(self, srv, username, password):
        challenge = self.call({"command": "GET_CHALLENGE", "username": username})["challenge"]
        response = hmac.new(st.CHALLENGE_KEY, challenge.encode(), hashlib.sha256).hexdigest()
        totp = pyotp.TOTP(srv.users[username]["totp_secret"]).now()
        return self.call({"command": "LOGIN", "username": username, "password": password,
                          "totp": totp, "challenge_response": response})


def test_commands_require_login(running_server):
    _, port = running_server
    client = RawClient(port)
    reply = client.call({"command": "SEND_MESSAGE", "recipient": "bob",
                         "ciphertext": "x", "nonce": "y"})
    assert reply["status"] == "error" and "Not logged in" in reply["message"]


def test_bad_challenge_response_blocks_login(running_server):
    srv, port = running_server
    srv.create_account("alice", "pw")
    client = RawClient(port)
    client.call({"command": "GET_CHALLENGE", "username": "alice"})
    reply = client.call({"command": "LOGIN", "username": "alice", "password": "pw",
                         "totp": "000000", "challenge_response": "forged"})
    assert reply["status"] == "error"


def test_server_relays_only_ciphertext(running_server, capsys):
    srv, port = running_server
    srv.create_account("alice", "pw-a")
    srv.create_account("bob", "pw-b")
    a, b = RawClient(port), RawClient(port)
    assert a.login(srv, "alice", "pw-a")["status"] == "success"
    assert b.login(srv, "bob", "pw-b")["status"] == "success"

    # Key agreement happens on the clients; the server never gets a private key.
    alice, bob = st.SecureTextClient(), st.SecureTextClient()
    alice.username, bob.username = "alice", "bob"
    alice.generate_ecdh_keypair()
    bob.generate_ecdh_keypair()
    alice.derive_session_key(bob.serialize_public_key(bob.ecdh_public_key), "bob")
    bob.derive_session_key(alice.serialize_public_key(alice.ecdh_public_key), "alice")

    secret = "meet at 5pm"
    nonce, ciphertext = alice.encrypt_message(secret, "bob")
    assert a.call({"command": "SEND_MESSAGE", "recipient": "bob",
                   "ciphertext": ciphertext, "nonce": nonce})["status"] == "success"

    delivered = b.reader.read_message()
    assert delivered["type"] == "MESSAGE" and delivered["from"] == "alice"
    assert bob.decrypt_message(delivered["nonce"], delivered["ciphertext"], "alice") == secret

    # Nothing the server printed or logged contains the plaintext.
    assert secret not in capsys.readouterr().out
    for log_file in ("auth.log", "messages.log"):
        try:
            assert secret not in open(log_file).read()
        except FileNotFoundError:
            pass

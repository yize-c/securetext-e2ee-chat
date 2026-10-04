#!/usr/bin/env python3
"""
SecureText: an end-to-end encrypted command-line chat

Security features implemented by Yize Chen on top of the SecureText
starter code by Ardeshir Shojaeinasab (MIT License).

Features:
  1. Salted PBKDF2-HMAC-SHA256 password storage
  2. TOTP two-factor auth (Google Authenticator) with QR code at signup
  3. GitHub OAuth login
  4. HMAC challenge-response before password/TOTP check
  5. Session timeout with warning, secure cleanup of keys
  6. Failed login tracking, audit log (auth.log), RBAC for admin commands
  7. Newline JSON framing over TCP
  8. ECDH (P-256) + HKDF key exchange, AES-GCM end-to-end encryption
"""

import socket
import threading
import json
import os
import sys
import time
from datetime import datetime

import hashlib
import hmac

import pyotp
import qrcode

import secrets
import webbrowser
import urllib.parse
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import base64

# Shared HMAC key for the challenge-response step. Set the same value in the
# server and client terminals; it is never stored in the source code.
CHALLENGE_KEY = os.environ.get("SECURETEXT_CHALLENGE_KEY", "").encode()
if not CHALLENGE_KEY:
    sys.exit("Set SECURETEXT_CHALLENGE_KEY before running (see README).")

PBKDF2_ITERATIONS = 100_000

SESSION_TIMEOUT = 30 * 60
WARNING_THRESHOLD = 5 * 60
SESSION_MONITOR_INTERVAL = 15


def send_json(sock, obj):
    """Send one JSON object, newline-terminated."""
    data = (json.dumps(obj) + '\n').encode('utf-8')
    sock.sendall(data)


class JsonFrameReader:
    """Reads one full JSON message at a time from a socket, buffering
    across recv() calls until a newline shows up."""
    def __init__(self, sock, recv_size=4096):
        self.sock = sock
        self.recv_size = recv_size
        self.buffer = b''

    def read_message(self):
        while b'\n' not in self.buffer:
            chunk = self.sock.recv(self.recv_size)
            if not chunk:
                return None
            self.buffer += chunk

        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line.decode('utf-8'))


class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.active_connections = {}
        self.last_activity = {}
        self.challenges = {}
        self.failed_attempts = {}
        self.warned_users = set()
        self.state_lock = threading.Lock()
        self.server_socket = None

    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
        return {}

    def save_users(self):
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")

    @staticmethod
    def _hash_password(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS)

    def generate_qr(self, username):
        secret = self.users[username]['totp_secret']

        uri = pyotp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="SecureText"
        )

        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make(fit=True)

        print("\n====================================")
        print(f"Scan this QR Code for {username}")
        print("====================================")

        qr.print_ascii(invert=True)

        print("\nSecret Key:", secret)
        print("====================================\n")

    def create_account(self, username, password):
        if username in self.users:
            return False, "Username already exists"

        salt = os.urandom(16)
        hashed_password = self._hash_password(password, salt)
        secret = pyotp.random_base32()

        self.users[username] = {
            'salt': salt.hex(),
            'password': hashed_password.hex(),
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue',
            'totp_secret': secret,
            'role': 'user'
        }

        self.save_users()
        self.generate_qr(username)

        return True, "Account created successfully"

    def authenticate(self, username, password, totp_code):
        if username not in self.users:
            return False, "Username not found"

        record = self.users[username]
        salt = bytes.fromhex(record['salt'])
        input_hash = self._hash_password(password, salt)

        if not hmac.compare_digest(input_hash, bytes.fromhex(record['password'])):
            return False, "Invalid password"

        secret = record['totp_secret']
        if not pyotp.TOTP(secret).verify(totp_code, valid_window=1):
            return False, "Invalid TOTP code"

        return True, "Authentication successful"

    def verify_challenge(self, username, response_value):
        if username not in self.challenges:
            return False

        challenge = self.challenges[username]
        expected = hmac.new(CHALLENGE_KEY, challenge.encode(), hashlib.sha256).hexdigest()

        del self.challenges[username]  # single-use

        return hmac.compare_digest(expected, response_value)

    def reset_password(self, username, new_password):
        if username not in self.users:
            return False, "Username not found"

        salt = os.urandom(16)
        hashed_password = self._hash_password(new_password, salt)

        self.users[username]['salt'] = salt.hex()
        self.users[username]['password'] = hashed_password.hex()
        self.save_users()
        return True, "Password reset successful"

    def log_action(self, event_type, username, detail, success=True):
        status = "SUCCESS" if success else "FAILED"
        log_entry = f"[{datetime.now().isoformat()}] {event_type} | user={username} | {detail} | {status}\n"

        with open('auth.log', 'a') as f:
            f.write(log_entry)

        print(log_entry.strip())

    def log_message(self, sender, recipient, ciphertext_b64, nonce_b64):
        """Ciphertext-only message log -- proves the server never stores plaintext."""
        entry = (f"[{datetime.now().isoformat()}] from={sender} to={recipient} "
                 f"nonce={nonce_b64} ciphertext={ciphertext_b64}\n")
        with open('messages.log', 'a') as f:
            f.write(entry)

    def oauth_login(self):
        client_id = os.environ.get("GITHUB_CLIENT_ID")
        client_secret = os.environ.get("GITHUB_CLIENT_SECRET")

        if not client_id or not client_secret:
            print("[OAuth Error] Missing environment variables")
            raise RuntimeError("Missing GitHub OAuth environment variables")

        state = secrets.token_hex(16)
        redirect_uri = "http://localhost:8080/oauth/callback"

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user",
            "state": state
        }

        auth_url = "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)
        webbrowser.open(auth_url)

        code_box = {}
        state_box = {}

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)

                if parsed.path != "/oauth/callback":
                    self.send_response(404)
                    self.end_headers()
                    return

                query = urllib.parse.parse_qs(parsed.query)
                code_box["code"] = query.get("code", [None])[0]
                state_box["state"] = query.get("state", [None])[0]

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OAuth success. You can close this tab.")

        server = HTTPServer(("localhost", 8080), CallbackHandler)
        server.handle_request()

        code = code_box.get("code")
        returned_state = state_box.get("state")

        if returned_state != state:
            print("[OAuth Error] state mismatch")
            return None

        token_resp = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "state": state
            },
            headers={"Accept": "application/json"}
        )

        access_token = token_resp.json().get("access_token")
        if not access_token:
            print("[OAuth Error] token failed")
            return None

        user_resp = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )

        user_data = user_resp.json()

        print("\n[OAuth Login Success]")
        print("GitHub:", user_data.get("login"))

        return user_data

    def handle_client(self, conn, addr):
        print(f"New connection from {addr}")
        current_user = None
        reader = JsonFrameReader(conn)

        try:
            while True:
                try:
                    message = reader.read_message()
                except json.JSONDecodeError:
                    send_json(conn, {'status': 'error', 'message': 'Invalid JSON'})
                    continue
                except socket.timeout:
                    continue

                if message is None:
                    break

                command = message.get('command')

                if current_user:
                    should_expire = False
                    should_warn = False
                    remaining = 0

                    with self.state_lock:
                        elapsed = time.time() - self.last_activity.get(current_user, 0)
                        remaining = SESSION_TIMEOUT - elapsed

                        if remaining <= 0:
                            should_expire = True
                            self.active_connections.pop(current_user, None)
                            self.last_activity.pop(current_user, None)
                            self.warned_users.discard(current_user)
                        elif remaining <= WARNING_THRESHOLD and current_user not in self.warned_users:
                            should_warn = True
                            self.warned_users.add(current_user)

                    if should_expire:
                        self.log_action('SESSION', current_user, 'Session expired', success=False)
                        current_user = None
                        send_json(conn, {'status': 'error', 'message': 'Session expired. Please log in again.'})
                        continue
                    elif should_warn:
                        send_json(conn, {
                            'type': 'SESSION_WARNING',
                            'remaining_seconds': int(remaining)
                        })

                if command == 'CREATE_ACCOUNT':
                    username = message.get('username')
                    password = message.get('password')
                    success, msg = self.create_account(username, password)
                    response = {'status': 'success' if success else 'error', 'message': msg}

                elif command == 'GET_CHALLENGE':
                    username = message.get('username')
                    challenge = secrets.token_hex(16)
                    self.challenges[username] = challenge
                    print(f"[Challenge] Sent to {username}: {challenge}")
                    response = {'status': 'success', 'challenge': challenge}

                elif command == 'LOGIN':
                    username = message.get('username')
                    challenge_response = message.get('challenge_response')

                    if not self.verify_challenge(username, challenge_response):
                        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                        if self.failed_attempts[username] >= 3:
                            print(f"[WARNING] {username} failed login 3+ times!")

                        self.log_action('LOGIN', username, 'challenge-response failed', success=False)
                        response = {'status': 'error', 'message': 'Invalid challenge response'}
                    else:
                        password = message.get('password')
                        totp_code = message.get('totp')
                        success, msg = self.authenticate(username, password, totp_code)

                        if success:
                            current_user = username
                            with self.state_lock:
                                self.active_connections[username] = conn
                                self.last_activity[username] = time.time()
                                self.warned_users.discard(username)
                            self.failed_attempts[username] = 0

                            self.log_action('LOGIN', username, 'password+TOTP+HMAC', success=True)
                        else:
                            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                            if self.failed_attempts[username] >= 3:
                                print(f"[WARNING] {username} failed login 3+ times!")

                            self.log_action('LOGIN', username, 'password+TOTP+HMAC', success=False)

                        response = {'status': 'success' if success else 'error', 'message': msg}

                elif command == 'OAUTH_LOGIN':
                    user_data = self.oauth_login()

                    if user_data:
                        github_username = user_data.get("login")
                        current_user = f"github:{github_username}"
                        with self.state_lock:
                            self.active_connections[current_user] = conn
                            self.last_activity[current_user] = time.time()
                            self.warned_users.discard(current_user)

                        self.log_action('OAUTH_LOGIN', current_user, 'GitHub OAuth', success=True)

                        response = {
                            'status': 'success',
                            'message': f'GitHub login as {github_username}',
                            'github_username': github_username
                        }
                    else:
                        self.log_action('OAUTH_LOGIN', 'UNKNOWN', 'GitHub OAuth', success=False)
                        response = {'status': 'error', 'message': 'OAuth login failed'}

                elif command == 'SEND_MESSAGE':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        recipient = message.get('recipient')
                        ciphertext_b64 = message.get('ciphertext')
                        nonce_b64 = message.get('nonce')

                        if not ciphertext_b64 or not nonce_b64:
                            response = {'status': 'error', 'message': 'Missing ciphertext or nonce'}
                        else:
                            print(f"[SEND_MESSAGE] server received from={current_user} "
                                  f"to={recipient} ciphertext={ciphertext_b64} nonce={nonce_b64}")
                            self.log_message(current_user, recipient, ciphertext_b64, nonce_b64)

                            with self.state_lock:
                                recipient_conn = self.active_connections.get(recipient)

                            if recipient_conn is None:
                                response = {'status': 'error', 'message': 'Recipient is offline'}
                            else:
                                msg_data = {
                                    'type': 'MESSAGE',
                                    'from': current_user,
                                    'ciphertext': ciphertext_b64,
                                    'nonce': nonce_b64,
                                    'timestamp': datetime.now().isoformat()
                                }
                                try:
                                    send_json(recipient_conn, msg_data)
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except Exception:
                                    with self.state_lock:
                                        self.active_connections.pop(recipient, None)
                                    response = {'status': 'error', 'message': 'Recipient is offline'}

                elif command == 'ECDH_PUBLIC_KEY':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        recipient = message.get('to')

                        forward_msg = {
                            'type': 'ECDH_PUBLIC_KEY',
                            'from': current_user,
                            'public_key': message.get('public_key')
                        }

                        with self.state_lock:
                            recipient_conn = self.active_connections.get(recipient)

                        if recipient_conn is None:
                            response = {'status': 'error', 'message': 'Recipient offline'}
                        else:
                            try:
                                send_json(recipient_conn, forward_msg)
                                response = {'status': 'success', 'message': 'Public key forwarded'}
                            except Exception:
                                with self.state_lock:
                                    self.active_connections.pop(recipient, None)
                                response = {'status': 'error', 'message': 'Recipient offline'}

                elif command == 'RESET_PASSWORD':
                    if not current_user:
                        self.log_action('RESET_PASSWORD', 'UNKNOWN', 'Access denied (not logged in)', success=False)
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        username = message.get('username')

                        if username != current_user and self.users.get(current_user, {}).get('role') != 'admin':
                            self.log_action(
                                'RESET_PASSWORD', current_user,
                                f'Access denied: tried to reset {username}', success=False
                            )
                            response = {'status': 'error', 'message': 'Access denied: admin only'}
                        else:
                            new_password = message.get('new_password')
                            success, msg = self.reset_password(username, new_password)
                            self.log_action('RESET_PASSWORD', current_user, f'target={username}', success=success)
                            response = {'status': 'success' if success else 'error', 'message': msg}

                elif command == 'GET_SESSION_INFO':
                    if not current_user:
                        response = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        with self.state_lock:
                            elapsed = time.time() - self.last_activity.get(current_user, 0)
                        remaining = max(0, int(SESSION_TIMEOUT - elapsed))
                        response = {
                            'status': 'success',
                            'username': current_user,
                            'remaining_seconds': remaining
                        }

                elif command == 'LIST_USERS':
                    if not current_user:
                        self.log_action('LIST_USERS', 'UNKNOWN', 'Access denied (not logged in)', success=False)
                        response = {'status': 'error', 'message': 'Not logged in'}
                    elif self.users.get(current_user, {}).get('role') != 'admin':
                        self.log_action('LIST_USERS', current_user, 'Access denied: not admin', success=False)
                        response = {'status': 'error', 'message': 'Access denied: admin only'}
                    else:
                        with self.state_lock:
                            online_users = list(self.active_connections.keys())
                        all_users = list(self.users.keys())
                        response = {
                            'status': 'success',
                            'online_users': online_users,
                            'all_users': all_users
                        }

                else:
                    response = {'status': 'error', 'message': 'Unknown command'}

                send_json(conn, response)

                if current_user:
                    with self.state_lock:
                        self.last_activity[current_user] = time.time()

        except ConnectionResetError:
            pass
        finally:
            if current_user:
                with self.state_lock:
                    self.active_connections.pop(current_user, None)
                    self.last_activity.pop(current_user, None)
            conn.close()
            print(f"Connection from {addr} closed")

    def session_monitor(self):
        """Background sweep so idle users still get warned/expired."""
        while True:
            time.sleep(SESSION_MONITOR_INTERVAL)

            with self.state_lock:
                snapshot = list(self.active_connections.items())

                for username, conn in snapshot:
                    elapsed = time.time() - self.last_activity.get(username, 0)
                    remaining = SESSION_TIMEOUT - elapsed

                    try:
                        if remaining <= 0:
                            self.active_connections.pop(username, None)
                            self.last_activity.pop(username, None)
                            self.warned_users.discard(username)
                            send_json(conn, {'status': 'error', 'message': 'Session expired. Please log in again.'})
                        elif remaining <= WARNING_THRESHOLD and username not in self.warned_users:
                            send_json(conn, {'type': 'SESSION_WARNING', 'remaining_seconds': int(remaining)})
                            self.warned_users.add(username)
                    except Exception:
                        continue

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")

            monitor_thread = threading.Thread(target=self.session_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()

            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()


class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.reader = None
        self.logged_in = False
        self.username = None
        self.running = False
        self.listen_thread = None

        self.ecdh_private_key = None
        self.ecdh_public_key = None
        self.session_keys = {}

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(0.5)
            self.reader = JsonFrameReader(self.socket)
            return True
        except ConnectionRefusedError:
            print("Error: Could not connect to server. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def send_command(self, command_data):
        try:
            send_json(self.socket, command_data)
            response = self.reader.read_message()
            if response is None:
                return {'status': 'error', 'message': 'Connection closed by server'}
            self._check_session_expired(response)
            return response
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}

    def _check_session_expired(self, response):
        if response.get('status') == 'error' and 'Session expired' in response.get('message', ''):
            self.secure_clear_session()
            self.logged_in = False

    def _send_command_paused(self, command_data):
        """Pause the listen thread while sending, so both don't read the
        socket at once."""
        self.running = False
        if self.listen_thread is not None:
            self.listen_thread.join(timeout=1.0)

        response = self.send_command(command_data)

        self.running = True
        self.listen_thread = threading.Thread(target=self.listen_for_messages)
        self.listen_thread.daemon = True
        self.listen_thread.start()

        return response

    def listen_for_messages(self):
        while self.running:
            try:
                message = self.reader.read_message()
                if message is None:
                    break
                if message.get('type') == 'MESSAGE':
                    sender = message.get('from')
                    plaintext = self.decrypt_message(
                        message.get('nonce'), message.get('ciphertext'), sender
                    )
                    print(f"\n[{message['timestamp']}] {sender}: {plaintext}")
                    print(">> ", end="", flush=True)
                elif message.get('type') == 'SESSION_WARNING':
                    remaining = message.get('remaining_seconds', 0)
                    print(f"\n[WARNING] Session expires in {remaining // 60} min "
                          f"{remaining % 60} sec -- re-login soon or you'll be logged out.")
                    print(">> ", end="", flush=True)
                elif message.get('status') == 'error' and 'Session expired' in message.get('message', ''):
                    self.secure_clear_session()
                    self.logged_in = False
                    print(f"\n[SESSION] {message['message']}")
                    print(">> ", end="", flush=True)
                elif message.get('type') == 'ECDH_PUBLIC_KEY':
                    peer = message.get('from')
                    is_new_session = peer not in self.session_keys

                    self.derive_session_key(message.get('public_key'), peer)
                    print(f"\n[ECDH] Session key established with {peer}")

                    if is_new_session:
                        if self.ecdh_public_key is None:
                            self.generate_ecdh_keypair()

                        self.send_command({
                            'command': 'ECDH_PUBLIC_KEY',
                            'to': peer,
                            'public_key': self.serialize_public_key(self.ecdh_public_key)
                        })

                    print(">> ", end="", flush=True)
            except socket.timeout:
                continue
            except Exception:
                break

    def generate_ecdh_keypair(self):
        """New key pair every login, for forward secrecy."""
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdh_public_key = self.ecdh_private_key.public_key()

        pub_bytes = self.serialize_public_key(self.ecdh_public_key).encode('utf-8')
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:16]
        print(f"[ECDH] New ephemeral key pair generated. Public key fingerprint: {fingerprint}")

    def serialize_public_key(self, public_key):
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    def derive_session_key(self, peer_public_key_pem, peer_username):
        print(f"[ECDH] Computing shared secret with {peer_username} using ECDH (P-256)...")
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode('utf-8')
        )
        shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key)
        print(f"[ECDH] Shared secret computed ({len(shared_secret)} bytes, not printed).")

        participants = sorted([self.username, peer_username])
        info = ("-".join(participants)).encode('utf-8')
        print(f"[ECDH] Deriving session key via HKDF-SHA256, info=\"{info.decode()}\"...")

        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info
        ).derive(shared_secret)

        key_fingerprint = hashlib.sha256(session_key).hexdigest()[:16]
        print(f"[ECDH] Session key derived. Key fingerprint: {key_fingerprint}")

        self.session_keys[peer_username] = session_key

    def initiate_key_exchange(self, peer_username):
        if self.ecdh_public_key is None:
            self.generate_ecdh_keypair()

        response = self._send_command_paused({
            'command': 'ECDH_PUBLIC_KEY',
            'to': peer_username,
            'public_key': self.serialize_public_key(self.ecdh_public_key)
        })
        return response

    def encrypt_message(self, plaintext, peer_username):
        session_key = self.session_keys.get(peer_username)
        if session_key is None:
            return None, None

        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data=None)

        return base64.b64encode(nonce).decode(), base64.b64encode(ciphertext).decode()

    def decrypt_message(self, nonce_b64, ciphertext_b64, peer_username):
        session_key = self.session_keys.get(peer_username)
        if session_key is None:
            return "[Cannot decrypt: no session key for this sender]"

        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception:
            return "[Cannot decrypt: malformed message]"

        aesgcm = AESGCM(session_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            return plaintext_bytes.decode('utf-8')
        except InvalidTag:
            print(f"[WARNING] Message from {peer_username} failed integrity check "
                  f"(InvalidTag) -- discarding.")
            return "[Message rejected: integrity check failed]"

    def secure_clear_session(self):
        """Best-effort wipe: overwrite key bytes with 0 before deleting."""
        peers = list(self.session_keys.keys())
        print(f"[SECURE CLEANUP] Wiping {len(peers)} session key(s) for: {peers}")

        for peer, key in list(self.session_keys.items()):
            wiped = bytearray(key)
            for i in range(len(wiped)):
                wiped[i] = 0
            del wiped
            del self.session_keys[peer]

        self.session_keys.clear()
        self.ecdh_private_key = None
        self.ecdh_public_key = None
        print("[SECURE CLEANUP] Session keys cleared. A new ECDH exchange is required for the next session.")

    def create_account(self):
        print("\n=== Create Account ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        if not username or not password:
            print("Username and password cannot be empty!")
            return

        command = {
            'command': 'CREATE_ACCOUNT',
            'username': username,
            'password': password
        }

        response = self.send_command(command)
        print(f"{response['message']}")

    def login(self):
        print("\n=== Login ===")
        username = input("Enter username: ").strip()

        cr = self.send_command({'command': 'GET_CHALLENGE', 'username': username})
        challenge = cr.get('challenge')

        if not challenge:
            print("Failed to get challenge")
            return

        cr_response = hmac.new(CHALLENGE_KEY, challenge.encode(), hashlib.sha256).hexdigest()

        password = input("Enter password: ").strip()
        totp = input("Enter 6-digit TOTP code: ").strip()

        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password,
            'totp': totp,
            'challenge_response': cr_response
        }

        response = self.send_command(command)
        print(f"{response['message']}")

        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
            self.running = True
            self.generate_ecdh_keypair()

            self.listen_thread = threading.Thread(target=self.listen_for_messages)
            self.listen_thread.daemon = True
            self.listen_thread.start()

    def github_login(self):
        command = {'command': 'OAUTH_LOGIN'}
        response = self.send_command(command)

        print(response['message'])

        if response['status'] == 'success':
            github_username = response.get('github_username', '')

            self.logged_in = True
            self.username = f"github:{github_username}"
            self.running = True
            self.generate_ecdh_keypair()

            self.listen_thread = threading.Thread(target=self.listen_for_messages)
            self.listen_thread.daemon = True
            self.listen_thread.start()

    def send_message(self):
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return

        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()

        if recipient not in self.session_keys:
            print(f"No E2EE session with {recipient} yet -- use "
                  f"'Start Secure (E2EE) Session with a User' first.")
            return

        content = input("Enter message: ").strip()

        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return

        nonce_b64, ciphertext_b64 = self.encrypt_message(content, recipient)
        if nonce_b64 is None:
            print(f"No E2EE session with {recipient} -- message not sent.")
            return

        response = self._send_command_paused({
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'ciphertext': ciphertext_b64,
            'nonce': nonce_b64
        })
        print(f"{response['message']}")

    def list_users(self):
        if not self.logged_in:
            print("You must be logged in to list users!")
            return

        response = self._send_command_paused({'command': 'LIST_USERS'})

        if response['status'] == 'success':
            print(f"\nOnline users: {', '.join(response['online_users'])}")
            print(f"All users: {', '.join(response['all_users'])}")
        else:
            print(f"Error: {response['message']}")

    def check_session_time(self):
        response = self._send_command_paused({'command': 'GET_SESSION_INFO'})

        if response['status'] == 'success':
            remaining = response['remaining_seconds']
            print(f"\nActive session for {response['username']}: "
                  f"{remaining // 60} min {remaining % 60} sec remaining.")
        else:
            print(f"Error: {response['message']}")

    def reset_password(self):
        print("\n=== Reset Password ===")
        username = input("Enter username: ").strip()
        new_password = input("Enter new password: ").strip()

        response = self._send_command_paused({
            'command': 'RESET_PASSWORD',
            'username': username,
            'new_password': new_password
        })
        print(f"{response['message']}")

    def run(self):
        if not self.connect():
            return

        print("=== SecureText Messenger ===")

        while True:
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Login with GitHub")
                print("4. Reset Password")
                print("5. Exit")
                choice = input("Choose an option: ").strip()

                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.github_login()
                elif choice == '4':
                    self.reset_password()
                elif choice == '5':
                    break
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Start Secure (E2EE) Session with a User")
                print("4. Check Session Time Remaining")
                print("5. Logout")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()

                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    peer = input("Enter username to establish an E2EE session with: ").strip()
                    if peer:
                        resp = self.initiate_key_exchange(peer)
                        print(f"{resp['message']}")
                elif choice == '4':
                    self.check_session_time()
                elif choice == '5':
                    self.secure_clear_session()
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out successfully")
                elif choice == '':
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")

        if self.socket:
            self.socket.close()
        print("Goodbye!")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        server = SecureTextServer()
        server.start_server()
    else:
        client = SecureTextClient()
        client.run()


if __name__ == "__main__":
    main()
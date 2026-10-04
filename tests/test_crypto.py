"""End-to-end encryption: ECDH key agreement, AES-GCM, tamper detection, key cleanup."""
import base64

import pytest

import securetext as st


def make_pair():
    alice, bob = st.SecureTextClient(), st.SecureTextClient()
    alice.username, bob.username = "alice", "bob"
    alice.generate_ecdh_keypair()
    bob.generate_ecdh_keypair()
    alice.derive_session_key(bob.serialize_public_key(bob.ecdh_public_key), "bob")
    bob.derive_session_key(alice.serialize_public_key(alice.ecdh_public_key), "alice")
    return alice, bob


def test_both_sides_derive_the_same_256_bit_key():
    alice, bob = make_pair()
    assert alice.session_keys["bob"] == bob.session_keys["alice"]
    assert len(alice.session_keys["bob"]) == 32


def test_different_pairs_get_different_keys():
    alice, bob = make_pair()
    carol = st.SecureTextClient()
    carol.username = "carol"
    carol.generate_ecdh_keypair()
    alice.derive_session_key(carol.serialize_public_key(carol.ecdh_public_key), "carol")
    assert alice.session_keys["carol"] != alice.session_keys["bob"]


def test_encrypt_then_decrypt_round_trip():
    alice, bob = make_pair()
    nonce, ciphertext = alice.encrypt_message("hello bob", "bob")
    assert bob.decrypt_message(nonce, ciphertext, "alice") == "hello bob"


def test_ciphertext_does_not_contain_plaintext():
    alice, _ = make_pair()
    _, ciphertext = alice.encrypt_message("top secret", "bob")
    assert b"top secret" not in base64.b64decode(ciphertext)


def test_same_message_encrypts_differently_each_time():
    alice, _ = make_pair()
    first = alice.encrypt_message("same text", "bob")
    second = alice.encrypt_message("same text", "bob")
    assert first[0] != second[0]  # fresh nonce
    assert first[1] != second[1]


def test_tampered_ciphertext_is_rejected():
    alice, bob = make_pair()
    nonce, ciphertext = alice.encrypt_message("pay $10", "bob")
    raw = bytearray(base64.b64decode(ciphertext))
    raw[0] ^= 0x01  # flip one bit
    tampered = base64.b64encode(bytes(raw)).decode()
    assert "integrity check failed" in bob.decrypt_message(nonce, tampered, "alice")


def test_message_from_unknown_peer_cannot_be_decrypted():
    alice, bob = make_pair()
    nonce, ciphertext = alice.encrypt_message("hi", "bob")
    assert "no session key" in bob.decrypt_message(nonce, ciphertext, "mallory")


def test_secure_cleanup_removes_all_keys():
    alice, _ = make_pair()
    alice.secure_clear_session()
    assert alice.session_keys == {}
    assert alice.ecdh_private_key is None
    assert alice.encrypt_message("hi", "bob") == (None, None)


@pytest.mark.parametrize("text", ["", "émoji 🔐", "x" * 10_000])
def test_round_trip_handles_edge_cases(text):
    alice, bob = make_pair()
    nonce, ciphertext = alice.encrypt_message(text, "bob")
    assert bob.decrypt_message(nonce, ciphertext, "alice") == text

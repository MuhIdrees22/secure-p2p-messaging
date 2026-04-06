# Diffie-Hellman key exchange implementation
# Member 2 — Faisal Akbar

import secrets

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)

DH_GENERATOR = 2


def generate_private_key():
    """Generate a random private key in range [2, p-2]."""
    return secrets.randbelow(DH_PRIME - 2) + 2


def generate_public_key(private_key):
    """Compute public key: A = g^a mod p"""
    return pow(DH_GENERATOR, private_key, DH_PRIME)


def compute_shared_secret(peer_public_key, private_key):
    """Compute shared secret: S = B^a mod p"""
    return pow(int(peer_public_key), private_key, DH_PRIME)

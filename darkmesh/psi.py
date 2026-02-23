import hashlib
import secrets
from typing import Iterable, List

# RFC 3526 Group 14 (2048-bit) prime in hex
_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

PRIME = int(_PRIME_HEX, 16)


def _hash_to_int(value: str, p: int) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest, 16) % p


def generate_secret(p: int = PRIME) -> int:
    # secrets.randbelow is inclusive of 0, exclude 0 and p-1
    return secrets.randbelow(p - 2) + 1


def blind_items(items: Iterable[str], secret: int, p: int = PRIME) -> List[int]:
    blinded = []
    for item in items:
        h = _hash_to_int(item, p)
        blinded.append(pow(h, secret, p))
    return blinded


def apply_secret(values: Iterable[int], secret: int, p: int = PRIME) -> List[int]:
    return [pow(v, secret, p) for v in values]


def encode_values(values: Iterable[int]) -> List[str]:
    return [format(v, "x") for v in values]


def decode_values(values: Iterable[str]) -> List[int]:
    return [int(v, 16) for v in values]


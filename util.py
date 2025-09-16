import hashlib, time, json, base64, os, struct, math, binascii

ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def double_sha256(b: bytes) -> bytes:
    return sha256(sha256(b))

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()

def now() -> int:
    return int(time.time())

def b58encode(b: bytes) -> str:
    # Base58 encoding (no 0OIl)
    num = int.from_bytes(b, 'big')
    enc = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(ALPHABET[rem])
    # leading zeros
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return (ALPHABET[0:1] * pad + enc[::-1]).decode()

def b58check_encode(payload: bytes, version: bytes=b'\x00') -> str:
    vh = version + payload
    checksum = double_sha256(vh)[:4]
    return b58encode(vh + checksum)

def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))

def merkle_root(tx_hashes: list[bytes]) -> bytes:
    if not tx_hashes:
        return b'\x00' * 32
    layer = tx_hashes[:]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else a
            nxt.append(double_sha256(a + b))
        layer = nxt
    return layer[0]

def to_json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)

def hexd(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def fromhex(s: str) -> bytes:
    return binascii.unhexlify(s)

def target_from_bits(bits: int) -> int:
    # 'bits' is number of leading zero bits required
    return 1 << (256 - bits)

def meets_pow(hash_bytes: bytes, bits: int) -> bool:
    return int.from_bytes(hash_bytes, 'big') < target_from_bits(bits)
from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError
from .util import sha256, hash160, b58check_encode

class KeyPair:
    def __init__(self, sk: SigningKey):
        self.sk = sk
        self.vk = sk.get_verifying_key()

    @staticmethod
    def generate():
        return KeyPair(SigningKey.generate(curve=SECP256k1))

    def sign(self, msg: bytes) -> bytes:
        return self.sk.sign_deterministic(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            return self.vk.verify(sig, msg)
        except BadSignatureError:
            return False

    def address(self) -> str:
        # Simplified P2PKH-like address
        pub_bytes = self.vk.to_string("compressed")
        h160 = hash160(pub_bytes)
        return b58check_encode(h160, b'\x00')

    def export(self) -> str:
        return self.sk.to_string().hex()

    @staticmethod
    def from_hex(hex_sk: str):
        sk = SigningKey.from_string(bytes.fromhex(hex_sk), curve=SECP256k1)
        return KeyPair(sk)

def verify_sig(pubkey_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        return vk.verify(sig, msg)
    except BadSignatureError:
        return False
    except Exception:
        return False
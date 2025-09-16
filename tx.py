from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple
import json
from .util import sha256, double_sha256, hexd
from .crypto import verify_sig

@dataclass
class TxOut:
    value: int               # integer coins
    address: str             # Base58Check address

@dataclass
class TxIn:
    txid: str                # hex of previous txid
    index: int               # output index
    pubkey: str              # hex compressed pubkey (33B)
    sig: Optional[str] = None # hex signature

@dataclass
class Transaction:
    inputs: List[TxIn]
    outputs: List[TxOut]
    note: str = ""

    def serialize(self) -> bytes:
        d = {
            "inputs": [asdict(i) for i in self.inputs],
            "outputs": [asdict(o) for o in self.outputs],
            "note": self.note,
        }
        return json.dumps(d, sort_keys=True).encode()

    def txid(self) -> str:
        return double_sha256(self.serialize()).hex()

    def sighash(self) -> bytes:
        # message to be signed
        return double_sha256(self.serialize())

    @staticmethod
    def coinbase(to_addr: str, amount: int, note: str="") -> "Transaction":
        return Transaction(inputs=[], outputs=[TxOut(value=amount, address=to_addr)], note=note)

    def verify(self) -> bool:
        # For each input, verify signature over sighash with provided pubkey
        msg = self.sighash()
        for ti in self.inputs:
            if not ti.sig:
                return False
            try:
                pub = bytes.fromhex(ti.pubkey)
                sig = bytes.fromhex(ti.sig)
            except Exception:
                return False
            if not verify_sig(pub, msg, sig):
                return False
        return True

# UTXO identifier type
UTXOKey = Tuple[str, int]  # (txid, index)
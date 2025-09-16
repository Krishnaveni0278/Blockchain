from dataclasses import dataclass, asdict
from typing import List
import json
from .util import double_sha256, merkle_root, now

@dataclass
class BlockHeader:
    prev_hash: str
    merkle_root: str
    timestamp: int
    difficulty: int
    nonce: int = 0

    def hash(self) -> str:
        data = json.dumps(asdict(self), sort_keys=True).encode()
        return double_sha256(data).hex()

@dataclass
class Block:
    header: BlockHeader
    txs: List[dict]  # store as plain dicts for persistence

    def block_hash(self) -> str:
        return self.header.hash()

    @staticmethod
    def from_txs(prev_hash: str, txs: List[dict], difficulty: int) -> "Block":
        import binascii
        import json as _json
        tx_hashes = []
        for t in txs:
            # txid is assumed set by creator (string hex)
            tx_hashes.append(binascii.unhexlify(t["txid"]))
        root = merkle_root(tx_hashes).hex()
        hdr = BlockHeader(prev_hash=prev_hash, merkle_root=root, timestamp=now(), difficulty=difficulty, nonce=0)
        return Block(header=hdr, txs=txs)
import json, os, binascii
from typing import Dict, Tuple, List
from dataclasses import asdict
from .util import double_sha256, meets_pow, target_from_bits, hexd, now
from .tx import Transaction, TxIn, TxOut, UTXOKey
from .block import Block, BlockHeader

DATA_DIR = "./data"
BLOCKS_FILE = os.path.join(DATA_DIR, "blocks.json")
MEMPOOL_FILE = os.path.join(DATA_DIR, "mempool.json")
WALLETS_FILE = os.path.join(DATA_DIR, "wallets.json")
DIFFICULTY_BITS = 18  # adjust for speed

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(BLOCKS_FILE):
        with open(BLOCKS_FILE, "w") as f:
            json.dump([], f)
    if not os.path.exists(MEMPOOL_FILE):
        with open(MEMPOOL_FILE, "w") as f:
            json.dump([], f)
    if not os.path.exists(WALLETS_FILE):
        with open(WALLETS_FILE, "w") as f:
            json.dump({}, f)

class Blockchain:
    def __init__(self):
        ensure_data_dir()
        self.chain: List[dict] = self._load_blocks()
        self.mempool: List[dict] = self._load_mempool()
        self.utxos: Dict[UTXOKey, TxOut] = {}
        self._rebuild_utxos()

    # ---------------- I/O ----------------
    def _load_blocks(self) -> List[dict]:
        with open(BLOCKS_FILE, "r") as f:
            return json.load(f)

    def _save_blocks(self):
        with open(BLOCKS_FILE, "w") as f:
            json.dump(self.chain, f, indent=2)

    def _load_mempool(self) -> List[dict]:
        with open(MEMPOOL_FILE, "r") as f:
            return json.load(f)

    def _save_mempool(self):
        with open(MEMPOOL_FILE, "w") as f:
            json.dump(self.mempool, f, indent=2)

    # ------------- Wallets (local) -------------
    def wallets(self) -> dict:
        with open(WALLETS_FILE, "r") as f:
            return json.load(f)

    def save_wallets(self, w: dict):
        with open(WALLETS_FILE, "w") as f:
            json.dump(w, f, indent=2)

    # ------------- UTXO helper -------------
    def _rebuild_utxos(self):
        self.utxos.clear()
        for b in self.chain:
            for idx, t in enumerate(b["txs"]):
                # add outputs
                for i, out in enumerate(t["outputs"]):
                    self.utxos[(t["txid"], i)] = TxOut(**out)
                # remove spent
                for ti in t["inputs"]:
                    if ti.get("txid") and ti.get("index") is not None:
                        self.utxos.pop((ti["txid"], ti["index"]), None)

    def find_spendable(self, address: str, amount: int) -> Tuple[int, List[UTXOKey]]:
        total, selected = 0, []
        for (txid, idx), out in self.utxos.items():
            if out.address == address:
                total += out.value
                selected.append((txid, idx))
                if total >= amount:
                    break
        return total, selected

    # ------------- TX pool -------------
    def add_tx(self, tx: Transaction) -> str:
        if not tx.verify():
            raise ValueError("Invalid signatures")
        # basic policy: ensure inputs are unspent and total_in >= total_out
        total_in = 0
        for ti in tx.inputs:
            utxo = self.utxos.get((ti.txid, ti.index))
            if not utxo:
                raise ValueError(f"Input spends missing UTXO {ti.txid}:{ti.index}")
            total_in += utxo.value
        total_out = sum(o.value for o in tx.outputs)
        if total_out > total_in:
            raise ValueError("Outputs exceed inputs")
        txd = {
            "inputs": [asdict(i) for i in tx.inputs],
            "outputs": [asdict(o) for o in tx.outputs],
            "note": tx.note,
            "txid": tx.txid(),
        }
        self.mempool.append(txd)
        self._save_mempool()
        return txd["txid"]

    # ------------- Mining -------------
    def mine(self, reward_to: str, reward_amount: int=50) -> dict:
        # assemble block from mempool + coinbase
        coinbase = Transaction.coinbase(reward_to, reward_amount, note="block-reward")
        coinbase_d = {
            "inputs": [],
            "outputs": [{"value": reward_amount, "address": reward_to}],
            "note": coinbase.note,
            "txid": coinbase.txid(),
        }
        txs = [coinbase_d] + self.mempool
        prev_hash = self.chain[-1]["header"]["hash"] if self.chain else "00"*32
        block = Block.from_txs(prev_hash, txs, DIFFICULTY_BITS)

        # PoW
        while True:
            h = bytes.fromhex(block.header.hash())
            if meets_pow(h, block.header.difficulty):
                break
            block.header.nonce += 1

        # persist
        header = asdict(block.header)
        header["hash"] = block.header.hash()
        bd = {"header": header, "txs": txs}
        self.chain.append(bd)
        self._save_blocks()
        self.mempool = []
        self._save_mempool()
        self._rebuild_utxos()
        return bd

    # ------------- Validation -------------
    def validate_chain(self) -> bool:
        prev = "00"*32
        for b in self.chain:
            hdr = b["header"]
            # check linkage
            if hdr["prev_hash"] != prev:
                return False
            # check PoW
            if not meets_pow(bytes.fromhex(hdr["hash"]), hdr["difficulty"]):
                return False
            # TODO: validate merkle root matches txs
            prev = hdr["hash"]
        return True

    # ------------- Balances -------------
    def balance(self, address: str) -> int:
        bal = 0
        for (txid, idx), out in self.utxos.items():
            if out.address == address:
                bal += out.value
        return bal
import os

from eth_account import Account
from solders.keypair import Keypair

# main.py reads these at import time; the RPC URL is unreachable so tests never touch a chain.
os.environ.setdefault("EVM_PRIVATE_KEY", Account.create().key.hex())
os.environ.setdefault("SVM_PRIVATE_KEY", str(Keypair()))
os.environ.setdefault("EVM_RPC_URL", "http://127.0.0.1:9")

from time import time
from model.printable import Printable


class Block(Printable):
    def __init__(self, index, previous_hash, proof, transactions, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.proof = proof
        self.transactions = transactions
        self.timestamp = time() if timestamp is None else timestamp

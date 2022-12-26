import util.hash_util as hl
from wallet import Wallet


class Verification:
    @staticmethod
    def valid_proof(transactions, last_hash, proof):
        guess = (str([tx.__dict__ for tx in transactions]) + str(last_hash) + str(proof)).encode()
        guess_hash = hl.hash_string_256(guess)
        return guess_hash[0:2] == '00'

    @staticmethod
    def verify_chain(blockchain):
        for (index, block) in enumerate(blockchain):
            if index == 0:
                continue
            if block.previous_hash != hl.hash_block(blockchain[index - 1]):
                return False
            if not Verification.valid_proof(block.transactions[:-1], block.previous_hash, block.proof):
                print('Invalid proof of work!')
                return False
        return True

    @staticmethod
    def verify_transaction(transaction, get_balance, check_funds=True):
        return get_balance(transaction.sender) >= transaction.amount and Wallet.verify_transaction(transaction)\
            if check_funds\
            else Wallet.verify_transaction(transaction)

    @staticmethod
    def verify_transactions(open_transactions, get_balance):
        return all([Verification.verify_transaction(tx, get_balance, False) for tx in open_transactions])

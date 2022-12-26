import json
from functools import reduce

import requests

from model.block import Block
from model.transaction import Transaction
from util.hash_util import hash_block
from util.verification import Verification as Verifier
from wallet import Wallet

MINING_REWARD = 10


class Blockchain:
    def __init__(self, public_key, node_id):
        self.public_key = public_key
        self.node_id = node_id

        self.__peer_nodes = set()
        self.__chain = [Block(0, '', 100, [], 0.0)]
        self.__open_transactions = []
        self.resolve_conflicts = False

        self.load_data()

    def get_chain(self):
        return self.__chain[:]

    def get_open_transactions(self):
        return self.__open_transactions[:]

    def load_data(self):
        try:
            with open(f'data/blockchain-{self.node_id}.txt', 'r') as f:
                file_content = f.readlines()

                self.__chain = json.loads(file_content[0][:-1])
                self.__chain = [Block(
                    block['index'],
                    block['previous_hash'],
                    block['proof'],
                    [Transaction(
                        tx['sender'],
                        tx['recipient'],
                        tx['amount'],
                        tx['signature']
                    ) for tx in block['transactions']],
                    block['timestamp']
                ) for block in self.__chain]

                self.__open_transactions = json.loads(file_content[1][:-1])
                self.__open_transactions = [Transaction(
                    tx['sender'],
                    tx['recipient'],
                    tx['amount'],
                    tx['signature']
                ) for tx in self.__open_transactions]

                peer_nodes = json.loads(file_content[2])
                self.__peer_nodes = set(peer_nodes)

        except (IOError, IndexError) as error:
            print(f'Error: {error}')

    def save_data(self):
        try:
            with open(f'data/blockchain-{self.node_id}.txt', 'w') as f:
                savable_chain = [block.__dict__ for block in
                                 [Block(
                                     block_el.index,
                                     block_el.previous_hash,
                                     block_el.proof,
                                     [tx.__dict__ for tx in block_el.transactions],
                                     block_el.timestamp)
                                     for block_el in self.__chain]]
                f.write(json.dumps(savable_chain))
                f.write('\n')
                savable_transactions = [tx.__dict__ for tx in self.__open_transactions]
                f.write(json.dumps(savable_transactions))
                f.write('\n')
                f.write(json.dumps(list(self.__peer_nodes)))

        except IOError as error:
            print(f'Saving failed : {error}')

    def proof_of_work(self):
        last_block = self.__chain[-1]
        last_hash = hash_block(last_block)
        proof = 0

        while not Verifier.valid_proof(self.__open_transactions, last_hash, proof):
            proof += 1
        return proof

    def get_balance(self, sender=None):
        if sender is None:
            if self.public_key is None:
                return None
            participant = self.public_key
        else:
            participant = sender

        tx_sender = [[tx.amount for tx in block.transactions if tx.sender == participant] for block in
                     self.__chain]
        open_tx_sender = [tx.amount for tx in self.__open_transactions if tx.sender == participant]

        tx_sender.append(open_tx_sender)
        amount_sent = reduce(lambda tx_sum, tx_amt: tx_sum + sum(tx_amt) if len(tx_amt) > 0 else tx_sum, tx_sender, 0)

        tx_recipient = [[tx.amount for tx in block.transactions if tx.recipient == participant] for block in
                        self.__chain]
        open_tx_recipient = [tx.amount for tx in self.__open_transactions if tx.recipient == participant]

        tx_recipient.append(open_tx_recipient)
        amount_received = reduce(lambda tx_sum, tx_amt: tx_sum + sum(tx_amt) if len(tx_amt) > 0 else tx_sum,
                                 tx_recipient, 0)

        return amount_received - amount_sent

    def add_transaction(self, tx_sender, tx_recipient, tx_signature, tx_amount=1.0, is_receiving=False):
        if self.public_key is None:
            return False

        transaction = Transaction(tx_sender, tx_recipient, tx_amount, tx_signature)
        if Verifier.verify_transaction(transaction, self.get_balance):
            self.__open_transactions.append(transaction)
            self.save_data()
            if not is_receiving:
                for node in self.__peer_nodes:
                    url = f'http://{node}/broadcast-transaction'
                    try:
                        response = requests.post(url, json={
                            'sender': tx_sender,
                            'recipient': tx_recipient,
                            'amount': tx_amount,
                            'signature': tx_signature
                        })
                        if response.status_code == 400 or response.status_code == 500:
                            print('Transaction declined, needs resolving')
                            return False
                    except requests.exceptions.ConnectionError:
                        continue
                return True
        return False

    def mine_block(self):
        if self.public_key is None:
            return None

        copied_transactions = self.__open_transactions[:]
        for tx in copied_transactions:
            if not Wallet.verify_transaction(tx):
                return False

        reward_transaction = Transaction('MINING', self.public_key, MINING_REWARD, '')
        copied_transactions.append(reward_transaction)

        last_block = self.__chain[-1]
        last_hash = hash_block(last_block)
        print('last block: ', last_block)
        print('last hash: ', last_hash)
        block = Block(
            len(self.__chain),
            last_hash,
            self.proof_of_work(),
            copied_transactions,
        )
        self.__chain.append(block)
        print('current block: ', block)

        self.__open_transactions = []
        self.save_data()

        for node in self.__peer_nodes:
            url = f'http://{node}/broadcast-block'
            converted_block = block.__dict__.copy()
            converted_block['transactions'] = [tx.__dict__ for tx in converted_block['transactions']]
            try:
                response = requests.post(url, json={'block': converted_block})
                if response.status_code == 400 or response.status_code == 500:
                    print('Block declined, needs resolving')
                if response.status_code == 409:
                    self.resolve_conflicts = True
            except requests.exceptions.ConnectionError:
                continue

        return block

    def add_block(self, block):
        transactions = [Transaction(
            tx['sender'],
            tx['recipient'],
            tx['amount'],
            tx['signature']
        ) for tx in block['transactions']]

        proof_is_valid = Verifier.valid_proof(transactions[:-1], block['previous_hash'], block['proof'])
        hashes_match = hash_block(self.__chain[-1]) == block['previous_hash']
        if not proof_is_valid or not hashes_match:
            return False

        converted_block = Block(
            block['index'],
            block['previous_hash'],
            block['proof'],
            transactions,
            block['timestamp'])
        self.__chain.append(converted_block)

        stored_transactions = self.__open_transactions[:]
        for itx in block['transactions']:
            for opentx in stored_transactions:
                if opentx.sender == itx['sender'] and opentx.recipient == itx['recipient'] and opentx.amount == itx[
                    'amount'] and opentx.signature == itx['signature']:
                    try:
                        self.__open_transactions.remove(opentx)
                    except ValueError:
                        print('Item was already removed')

        # self.__open_transactions = []
        self.save_data()
        return True

    def resolve(self):
        winner_chain = self.__chain
        replace = False
        for node in self.__peer_nodes:
            url = f'http://{node}/chain'
            try:
                response = requests.get(url)
                node_chain = response.json()
                node_chain = [Block(
                    block['index'],
                    block['previous_hash'],
                    block['proof'],
                    [Transaction(
                        tx['sender'],
                        tx['recipient'],
                        tx['amount'],
                        tx['signature']
                    ) for tx in block['transactions']],
                    block['timestamp']
                ) for block in node_chain]

                node_chain_length = len(node_chain)
                local_chain_length = len(winner_chain)
                if node_chain_length > local_chain_length and Verifier.verify_chain(node_chain):
                    winner_chain = node_chain
                    replace = True
            except requests.exceptions.ConnectionError as error:
                print(f'Error occurred: {error}')
                continue
        self.resolve_conflicts = False
        self.__chain = winner_chain
        if replace:
            self.__open_transactions = []
        self.save_data()
        return replace

    def add_peer_node(self, node):
        self.__peer_nodes.add(node)
        self.save_data()

    def remove_peer_node(self, node):
        self.__peer_nodes.discard(node)
        self.save_data()

    def get_peer_nodes(self):
        return list(self.__peer_nodes)

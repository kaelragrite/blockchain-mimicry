import hashlib
import json


def hash_string_256(string):
    return hashlib.sha256(string).hexdigest()


def hash_block(block):
    hashable_block = block.__dict__.copy()
    hashable_block['transactions'] = [tx.__dict__ for tx in hashable_block['transactions']]
    print('hashable_block: ', hashable_block)
    return hashlib.sha256(json.dumps(hashable_block, sort_keys=True).encode()).hexdigest()

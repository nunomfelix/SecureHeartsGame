import hashlib
from termcolor import colored
from datetime import datetime 
from time import time
import json

class Blockchain():
    def __init__(self):
        print(colored('Generating genesis block..','green'))
        self.blocks = [self.genesis_block()]
        self.current_txs = []
        self.confirmed_txs = []

    def genesis_block(self):
        return {
            'index': 0,
            'timestamp': self.generate_timestamp(),
            'transactions': '',
            'previous_hash': '',
        }
    
    def new_transaction(self, sender, recipient, msg):
        self.current_txs.append({
            'sender': sender,
            'recipient': recipient,
            'msg': msg

        })

    def get_chain(self):
        return self.blocks

    def get_chain_size(self):
        return len(self.blocks)-1

    def last_block(self):
        return self.blocks[-1]
    
    def new_block(self, previous_hash, txs):
        return {
            'index': len(self.blocks) + 1,
            'timestamp': self.generate_timestamp(),
            'transactions': txs,
            'previous_hash': previous_hash
        }

    def add_block(self, block):
        self.blocks.append(block)

    @staticmethod
    def generate_timestamp():
        now = datetime.now()
        return datetime.timestamp(now)

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            last_block = block
            current_index += 1

        return True
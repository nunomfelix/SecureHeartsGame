from diffieHellman_encrypt import DiffieHellman
from RSA import *
import random
import secrets
import hashlib
from blockchain.blockchain import Blockchain
from sym_crypto import *
import random
from Crypto.Cipher import DES3
from Crypto import Random
from cryptography.fernet import Fernet

class Client:
    def __init__(self):
        self.sid = ''
        self.sym_key = ''
        self.table_id = ''
        self.hand = []
        self.public_key = ''
        self.players = []
        self.players_in_table = []  # sid dos jogadores
        self.diffielman = DiffieHellman()
        self.priv_key = ''
        self.pub_key = ''
        self.rsa_keys = ''
        self.server_pub_RSA = ''
        self.R1 = 0
        self.R2 = 0
        self.bit_c = ''
        self.message_decrypt = ''
        self.count_sym = 0
        self.encrypted_hand = []
        self.current_txs = []
        self.sym_encrypt = '' 
        self.blockchain_copy = Blockchain()

    def takeCard(self, deck, valid_cards):
        total_cards = valid_cards
        i = 0
        n = '00000000'.encode()
        length = len(deck)

        while(i < length):
            if(deck[i] == n):
                deck.remove(deck[i])
                length = length - 1
                continue
            i = i+1

        index = random.randint(0, valid_cards-1)
        if random.randrange(100) > 50 and len(self.hand) < 13:
            card = deck[index]
            deck.pop(index)
            print('tirei carta ------')
            total_cards -= 1
            self.hand.append(card)
        else:
            # trocar cartas
            if len(self.hand) > 0:
                swap_num = random.randint(0, len(self.hand) - 1)
            else:
                swap_num = 0
            if swap_num <= len(deck) and swap_num != 0:

                cards_to_deck = []
                cards_to_hand = []

                for x in range(swap_num):
                    index_deck = random.randint(0, len(deck)-1)
                    index_hand = random.randint(0, len(self.hand)-1)
                    cards_to_hand.append(deck[index_deck])
                    cards_to_deck.append(self.hand[index_hand])
                    del deck[index_deck]
                    del self.hand[index_hand]

                self.hand.extend(cards_to_hand)
                deck.extend(cards_to_deck)

        players_ = self.players_in_table
        for x in players_:
            if self.sid == x:
                players_.remove(self.sid)
        next_player = random.choice(players_)
        deck = deck + ['00000000'.encode()]*(52 - len(deck))
        return deck, total_cards, next_player

    def generate_key(self, min, max):
        return secrets.token_bytes(random.randint(min, max))

    def bit_commitment(self):
        self.R1 = self.generate_key(16, 16)
        self.R2 = self.generate_key(16, 16)
        hashB = hashlib.sha256()
        hashB.update(self.R1)
        hashB.update(self.R2)
        for c in self.hand:
            hashB.update(c)
        hexB = hashB.hexdigest()
        self.bit_c = hexB
        return hexB

    def tryDecrypt(self, message):
        for x in self.players:
            try:
                self.message_decrypt = self.diffielman.decrypt(self.diffielman.seralize_pubKey(x['DH_pubKey']), message, x['IV'])
                if self.message_decrypt != '':
                    try:
                        self.message_decrypt = self.message_decrypt
                        return True
                    except UnicodeDecodeError:
                        self.message_decrypt = ''
            except ValueError:
                self.message_decrypt = ''
        return False

    def decrypt_hand(self,order):
        self.encrypted_hand = self.hand
        order.reverse()
        new_hand = []
        for card in self.hand:
            unciphered_card = card
            for sid in order:
                for x in self.players:
                    if x['sid'] == sid:
                        key = x['sym_key']
                        iv = x['sym_iv']
                        unciphered_card = self.sym_encrypt.decrypt(unciphered_card,key,iv)
                        
            new_hand.append(self.unpadding(unciphered_card.decode()))
        self.hand = new_hand
        
    def unpadding(self, card):
        return card[8:]


from deck import Deck
from config import *
from blockchain.blockchain import Blockchain
from sym_crypto import *
import hashlib

class Table:

    def __init__(self, _id):
        self.clients = []
        self.players = []
        self.state = ''
        self.table_id = _id
        self.count_encrypt=0
        self.deck = Deck()
        self.keychain = dict()
        self.count_encrypt2=0
        self.table_cards = ['','','','']
        self.score = [0,0,0,0]
        self.shuffled_deck = []
        self.count_ready = 0
        self.first_player = ''
        self.num_plays = 0
        self.count_played = 0
        self.winner = ''
        self.waiting_players = 0
        self.sym_keys = []
        self.encrypt_order = []
        self.count_verify_tx = 0
        self.cheating = {}
        self.encryptAlg = []
        self.sym_encrypt = ''
        self.current_card = ''
        self.plays = [{'name': '', 'card': ''},{'name': '', 'card': ''},{'name': '', 'card': ''},{'name': '', 'card': ''}]
        self.log_plays = []
        self.sym_algoritm = ''
        self.scoreboard = {}

        self.chain = Blockchain()

    def add_client(self,id):
        if(len(self.clients) < 4):
            self.clients.append(id)
            return True
        return False

    def remove_client(self, sid):
        self.clients.remove(sid)

    def num_of_players(self):
        return len(self.players)

    def add_score(self, winner, points):
        self.score[self.clients.index(winner)] = self.score[self.clients.index(winner)] + points

    def num_of_clients(self):
        return len(self.clients)

    def remove_player(self,sid):
        for p in self.players:
            if p['sid'] == sid:
                del p    
        return len(self.players)

    def checkHand_Winner(self):
        winner = self.first_player
        players = self.clients
        cards = self.table_cards
        print('cards: ' + str(cards))
        points = 0
        first_card = cards[players.index(winner)]
        print('First card played: ' + str(first_card))
        first_suit = first_card[7] # last char
        tmp_higherCard = first_card
        for card in cards:
            if card[7] == first_suit:
                if int(card[5:7]) > int(tmp_higherCard[5:7]):
                    tmp_higherCard = card
        for card in cards:
            if card[7] == 'H':
                points += 1
            if card == '0000012S':
                points += 13
        winner = self.clients[self.table_cards.index(tmp_higherCard)]   
        self.add_score(winner, points)
        return winner

    def check_endGame(self):
        if max(self.score) >= 100:
            self.winner = self.clients[self.score.index(min(self.score))]
            return self.winner
        else:
            return None

    def check_cheating(self):
        cheating_type = self.cheating['type']
        if cheating_type == 'cheating_played_my_card':
            for player in self.players:
                if player['sid'] == self.cheating['reported']:
                    R1 = player['R1']
                    R2 = player['R2']
                    hand = player['encrypt_hand']
                    bit = player['bit_commit']
            bit2 = self.bit_commitment(R1,R2,hand)
            if bit != bit2:
                #adulterou a mao inicial
                return True
            else:
                cards = self.decrypt_hand(hand)

                for card in cards:
                    if card == self.cheating['card']:
                        return False
                return True
                 
        elif cheating_type == 'cheating_played_the_same_card':
            for player in self.players:
                if player['sid'] == self.cheating['reported']:
                    reported_name = player['name']
            for play in self.plays:
                #sid_report = self.players['sid']
                if play['name'] == reported_name:
                    card = play['card']
                    break  
            for log in self.log_plays:
                for play in log:
                    if play['name'] == reported_name:
                        if card == play['card']:
                            return True 

        elif cheating_type == 'cheating_player_didnt_assist':
            for player in self.players:
                if player['sid'] == self.cheating['reported']:
                    reported_name = player['name']
            for play in self.plays:
                if play['name'] == reported_name:
                    suit = play['card'][7]
            for log in self.log_plays:
                first_suit = log[0]['card'][7]
                if suit == first_suit:
                    for play in log:
                        if play['name'] == reported_name:
                            card = play['card']
                            if card[7] != first_suit:
                                return True 
        return False

    def bit_commitment(self,R1,R2,hand):   
        hashB = hashlib.sha256()
        hashB.update(R1)
        hashB.update(R2)
        for c in hand:
            hashB.update(c)
        hexB = hashB.hexdigest()
        return hexB

    def decrypt_hand(self,hand):
        sym_decrypt = sym_crypto(self.sym_algoritm)
        order = self.encrypt_order
        order.reverse()
        new_hand = []
        for card in hand:
            unciphered_card = card
            for sid in order:
                for x in self.players:
                    if x['sid'] == sid:
                        key = x['sym_key']
                        iv = x['sym_iv']             
                        unciphered_card = sym_decrypt.decrypt(unciphered_card,key,iv)              
            new_hand.append(self.unpadding(unciphered_card.decode()))
        return new_hand

    def unpadding(self, card):
        return card[8:]
            

from config import suits, minNumber, maxNumber
import random
import json

class Deck:
    
    values = [x for x in range(2, 15)]
    suites = ['C', 'S', 'H', 'D']
    def __init__(self):
        self.deck = self.generate_cards()
    
    def add_cards(self, cards):
        self.deck = self.deck + cards
    def generate_cards(self):
        cards = []
        for suit in self.suites:
            for value in self.values:
                cards.append(Card(value, suit).__dict__)

        random.shuffle(cards)
        return cards

    def shuffle(self):
        return random.shuffle(self.deck)

    def has_cards(self):
        return self.deck

    def sort(self):
        return self.deck.sort()

    def size(self):
        return len(self.deck)

    def get_cards(self):
        if self.deck:
            return self.deck.pop()

    def get_deck(self):
        return self.deck

    def get_encoded_deck(self):
        return [(str(card['number'])+str(card['suit'])).encode() for card in self.deck]

    def __str__(self):
        s = ''
        for card in self.deck:
            s = s + ''.join(card.__str__()) + ' '
        return s

class Card:
    def __init__(self, number, suit):
        self.number=number
        self.suit=suit

    def get_card_image(self):
        from urllib.request import Request, urlopen
        from PIL import Image
        card = self.__str__().upper()
        url = 'https://deckofcardsapi.com/static/img/{}.png'.format(card)
        req = Request(url,headers={'User-Agent': 'Mozilla/5.0'})
        webp = urlopen(req)
        img = Image.open(webp)
        img.show()
    
    def __str__(self):
        if self.number < 11 and self.number > 0:
            return str(self.number)+str(self.suit)
        elif self.number == 11:
            return "J"+str(self.suit)
        elif self.number == 12:
            return "Q"+str(self.suit)
        elif self.number == 13:
            return "K"+str(self.suit)
        elif self.number == 14:
            return "A"+str(self.suit)
        else:
            print(str("Invalid card"))
            return (self.number + ' ' + self.suit)

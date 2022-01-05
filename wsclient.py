import socketio
import json
import string 
import random
from Crypto.Cipher import DES3
from cryptography.fernet import Fernet
from Crypto import Random
import RSA
import asyncio
import cc
import os
import base64
import names
import sys
from aioconsole import ainput
import base64
from sym_crypto import *
from client import * 

from termcolor import colored
from random import randrange
import pprint
player = []
sid__ = ''
name = ''
loop = asyncio.get_event_loop()
sio = socketio.AsyncClient()

pp = pprint.PrettyPrinter()

client = Client()
client.bot = 0

def find_player_by_sid(sid):
    for p in client.players:
        if p['sid'] == sid:
            return p

def add_padding_to_card(card):
    return card.rjust(8,'0')

async def choose_table(): 
    print('Choose table: ')
    table = await read_input()  
    print('1 - AES')
    print('2 - Camellia')
    print('3 - IDEA')
    print('4 - CAST5')
    print('5 - SEED')
    print('6 - BlowFish')
    print('Choose symmetric Algoritm:')
    alg = await read_input()
    if alg == '1':
        algoritm = 'AES'
    elif alg == '2':
        algoritm = 'Camellia'
    elif alg == '3':
        algoritm = 'IDEA'
    elif alg == '4':
        algoritm = 'CAST5'
    elif alg == '5':
        algoritm = 'SEED'
    elif alg == '6':
        algoritm = 'BlowFish'
    else:
        algoritm = 'default'
    await sio.emit('start', {'status':'choosing table', 'table': str(table), 'algoritm': algoritm})

@sio.on('connect')
async def connect(*args):
    if args != ():
        print(str(args))
    print('Connected! time to choose de table\n')
    await sio.emit('see_tables', {'status':'choosing table'})

@sio.on('choose_table')
async def choose_room(data):
    tables = data['tables']
    table_id = 1
    for table in tables:
        print('Table {}: {} '.format(str(table_id),table))
        table_id += 1
    await choose_table()

@sio.event
def disconnect():
    print('Disconnected!')
    print('removing generated keys')

@sio.event
async def enter(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA), data['status']):
        client.sid = data['sid']
        client.table_id = data['table_id']
        print('waiting for players in table {}'.format(data['table_id']))
        msg = 'waiting_4_players'
        await sio.emit('waiting', {'status': msg, 'signature': client.rsa_keys.sign_message(msg) })

@sio.on('request_encrypted_deck')
async def encrypted_deck(data):   
    print(str(data))
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA), data['status']):
        print(colored('Server requesting encrypted deck to {}'.format(data['requested_player']), 'red'))
        if data['deck'] and (data['requested_player'] == client.sid):
            print(colored('IM REQUESTED PLAYER {}'.format(client.sid), 'green'))
            print(data['players_in_table'])
            client.players_in_table = data['players_in_table']
            encrypt_deck = []
            client.sym_encrypt = sym_crypto(data['algoritm'])
            client.sym_key = client.sym_encrypt.key
            for card in data['deck']:
                ciphered_card =  client.sym_encrypt.encrypt(card)
                encrypt_deck.append(ciphered_card)    
            await sio.emit('encrypt_deck', {'status':'encrypted','table':client.table_id, 'deck': encrypt_deck, 'signature': client.rsa_keys.sign_message(str(encrypt_deck))})    
        else:
            await sio.emit('error', {'error':'no deck sent by server'})

@sio.on('check_player_id')
async def receive_players(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):
        if data['players']:
            citizen_card = cc.CitizenCard()
            client.players = json.loads(data['players']) 
            verified_list = {}
            for p in client.players:
                if p['sid'] != client.sid:
                    print(type(p['cert']+'\n'))
                    print(type(p['data_to_be_signed']))
                    print(type( p['signature']))
                    cert = base64.b64decode(p['cert'])
                    signature = base64.b64decode(p['signature'])
                
                    verification = citizen_card.verifySign(cert, p['data_to_be_signed'], signature)
                    verified_list[p['sid']] = verification
            if all(verified_list.values()):
                msg = 'ready_to_encrypt'
                await sio.emit('waiting', {'status': msg, 'signature': client.rsa_keys.sign_message(msg)})
            else:
                failed = []
                for k, v in verified_list:
                    if v == False:
                        failed.append(k)
                        string += str(k) + ' '
                msg = 'failed authentication in players ' + string
                await sio.emit('error', {'status': msg})
    else:
        await sio.emit('error',{'error': 'error in signature sent by server'})

@sio.on('send_sym_key')
async def send_symmetric_key(data):
    print(colored('Server requesting symmetric key','red'))
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):
        total_msg = []
        key = base64.b64encode(client.sym_key).decode('utf-8')
        sym_iv = base64.b64encode(client.sym_encrypt.sym_iv).decode('utf-8')
        message = {'key': key, 'sid': client.sid, 'sym_iv': sym_iv}
        for x in client.players:
            pub_key = x['DH_pubKey']
            message_ = client.diffielman.encrypt(client.diffielman.seralize_pubKey(pub_key),json.dumps(message))
            total_msg.append(message_)    
        await sio.emit('cipher_channel', {'status': 'pass_sym_key','message': total_msg,'table': client.table_id})

@sio.on('receive_sym_key')
async def receive_sym_key(data):
    for msg in data['message']: 
        if client.tryDecrypt(msg):      
            data = client.message_decrypt
            data = json.loads(data)
            for x in client.players:
                if x['sid'] == data['sid']:
                    x.update( {'sym_key': base64.b64decode(data['key'])})
                    x.update( {'sym_iv': base64.b64decode(data['sym_iv'])})  
    count = 0
    for x in client.players:
            for k in x:
                if k == 'sym_key':
                    count += 1     
    if count == 4:
        msg = 'have_all_sym_keys'
        await sio.emit('waiting', {'status': msg , 'signature': client.rsa_keys.sign_message(msg)})
        
@sio.on('cc_auth')
async def authentication(data):
    client.server_pub_RSA = data['server_public']

    citizen_card = cc.CitizenCard()


    cc_name = ''
    fake_name = (names.get_first_name() + names.get_last_name()) 
    if cc_name == os.path.isfile(cc_name+'_privRSA.pem'):
        cc_name = cc_name+str(randrange(1,100))
    else:
        cc_name = fake_name
    #gerar chave publica
    client.name = cc_name
    client.rsa_keys = RSA(client.name)
    server_public = client.rsa_keys.load_pub(data['server_public'])
    #funcrypto.generate_assym_key(1024, name+'.pub', name+'.priv')
    public_key = client.rsa_keys.read_pub(client.name+'_pubRSA.pem')
    private_key = client.rsa_keys.read_priv(client.name+'_privRSA.pem')
    cert = citizen_card.getCerts(0)
    cert = base64.b64encode(cert).decode('utf-8')

    # cert = ''
    signature = citizen_card.sign(0, cert+public_key+cc_name)

    if client.rsa_keys.verify_sig(data['signature'], server_public, data['status']):
        await sio.emit('verify_auth', {'cert': cert , 'data': cert+public_key+cc_name ,'signature': signature, 'public_key': public_key})
    else:
        await sio.emit('error', {})

@sio.on('error')
async def error_handling(data):
    print(str(data))


@sio.on('take_cards')
async def send_deck(data):
    if 'signature' in data:  # and data['next_player'] == client.sid:
        if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):
            if data['valid_cards'] != 0:
                if data['deck'] and (data['next_player'] == client.sid):
                    
                    deck, total_cards, next_player  = client.takeCard(data['deck'],data['valid_cards'])
                    deck = [base64.b64encode(card).decode('utf-8') for card in deck]

                    message = {'deck':deck ,'valid_cards': total_cards}
                    pub_key = ''
                    for x in client.players:
                        if x['sid'] == next_player:
                            pub_key = x['DH_pubKey']
                    
                    message = client.diffielman.encrypt(client.diffielman.seralize_pubKey(pub_key), json.dumps(message))
                    print('entrei')

                    #print(str({'status': 'passing_cards', 'table': client.table_id, 'valid_cards': total_cards, 'next_player': next_player}))
                    await sio.emit('cipher_channel', {'status': 'pass_deck','message': message,'table': client.table_id})
            else:
                await sio.emit('finish_pass', {'status': 'passing_finish', 'table': client.table_id, 'deck': data['deck']})
    elif client.tryDecrypt(data['message']):
        
        data = client.message_decrypt
        data = json.loads(data)
        
        if data['valid_cards'] != 0:
            if data['deck']:
                deck = [base64.b64decode(card) for card in data['deck']]

                deck, total_cards, next_player  = client.takeCard(deck,data['valid_cards'])
               
                deck = [base64.b64encode(card).decode('utf-8') for card in deck]

                message = {'deck':deck ,'valid_cards': total_cards}
                pub_key = ''
                for x in client.players:
                    if x['sid'] == next_player:
                        pub_key = x['DH_pubKey']
                
                message = client.diffielman.encrypt(client.diffielman.seralize_pubKey(pub_key), json.dumps(message))
                #print(str({'status': 'passing_cards', 'table': client.table_id, 'valid_cards': total_cards, 'next_player': next_player}))
                await sio.emit('cipher_channel', {'status': 'pass_deck','message': message,'table': client.table_id})
        else:
            await sio.emit('finish_pass', {'status': 'passing_finish', 'table': client.table_id, 'deck': data['deck'], 'valid_cards': data['valid_cards']})

@sio.on('check_empty')
async def check_empty(data):
    if data['valid_cards'] == 0:
        msg = 'ready_to_decrypt_hand'
        bit_commit = client.bit_commitment()
        print(type(bit_commit))
        print(str(bit_commit))
        await sio.emit('waiting', {'status': msg + bit_commit , 'bit_commit': bit_commit, 'R1': client.R1, 'signature': client.rsa_keys.sign_message(msg+bit_commit)})

@sio.on('create_secure_channel')
async def create_secure_channel(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):
        key = client.diffielman.convert_pubKey()
        IV = client.diffielman.IV
        await sio.emit('pass_public_channel', {'status': 'send key', 'key': key, 'IV': IV, 'signature': client.rsa_keys.sign_message(key)})

@sio.on('receive_keys_channel')
async def save_DH_keys(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):

        sid = data['sid']
        key = data['key']
        IV = data['IV']
        count = 0
        for x in client.players:
            if x['sid'] == sid:
                
                x.update( {'DH_pubKey': key})
                
                x.update({'IV': IV})
        
        #print('-----------{}'.format(str(client.players)))
        for x in client.players:
            #print(str(x))
            for k in x:

                if k == 'DH_pubKey':
                    count += 1
        
        if count == 4:
            msg = 'ready_to_pass_deck'
            await sio.emit('waiting', {'status': msg , 'signature': client.rsa_keys.sign_message(msg)})
        


@sio.on('request_2C')
async def check_firstToPlay(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA),data['status']):
        
        client.decrypt_hand(data['order'])
    
        if '0000002C' in client.hand:
            print('eu tenho o 2C')
            await sio.emit('ready_to_start_playing',{'status': 'ready!'})

async def read_input():
    input_ = await ainput("")
    return input_

@sio.on('play_card')
async def choose_card(data):   # data -- contem, cartas na mesa por ordem consoante a disposicao dos jogadores
    cards_played = data['cards_played']
    points = data['points']
    plays = [json.loads(play) for play in data['plays']]
    cards = [play['card'] if play['card'] != '' else ' ' for play in plays]
    names = [play['name'] for play in plays]
    print(str(plays))
    print('CARDS IN TABLE\n')
    print('-- {}   |  {}  |  {}  |  {}  ---\n'.format(names[0],names[1],names[2],names[3]))
    print('-----1------2------3------4-----\n')
    print('--  {}  |  {}  |  {}  |  {}  ---\n'.format(cards[0],cards[1],cards[2],cards[3]))
    print('--------------------------------\n')
    print('POINTS:\n')
    print('-----1------2------3------4-----\n')
    print('--  {}  |  {}  |  {}  |  {}  ---\n'.format(points[0],points[1],points[2],points[3]))
    print('--------------------------------\n')

    print('Cards in hand: \n')
    
    print(str(client.hand) + '\n')
    
    if client.bot == 0:
        print('1- Play Card')
        print('2- Report cheating')
        print('Option: ')
        input_ = await read_input()
        if input_== '1': 
            card_input = await read_input()

            card = add_padding_to_card(card_input)
            if card in client.hand:
                client.hand.remove(card)

            signature = client.rsa_keys.sign_message(card)
            
            await sio.emit('card_played', {'status':'playing','table':client.table_id, 'card': card , 'signature': signature})
        elif input_== '2':
            print('Report\n')
            print('1 - Player played my card')
            print('2-  Player played the same card')
            print('3 - Player didnt assist')
            print('cheating Option:')
            cheating_type = await read_input()

            print('Players ')
            for i in client.players:
                print(str(client.players.index(i) + 1)+' - '+ i['name'])
            print('Identify player:')
            cheater = await read_input()
            player = client.players[int(cheater)-1]['sid']

            if cheating_type == '1':
                print('card:')
                reported_card = await read_input()
                card = add_padding_to_card(str(reported_card))

                msg = 'cheating_played_my_card'
                await sio.emit('waiting', {'status': msg, 'check_player': player,'card': card,  'signature': client.rsa_keys.sign_message(msg)})
            elif cheating_type == '2': 
                msg = 'cheating_played_the_same_card'
                await sio.emit('waiting', {'status': msg,'check_player': player, 'signature': client.rsa_keys.sign_message(msg)})
            elif cheating_type == '3':
                msg = 'cheating_player_didnt_assist'
                await sio.emit('waiting', {'status': msg,'check_player': player, 'signature': client.rsa_keys.sign_message(msg)})
            else:
                print(str('invalid input'))
        
        else: 
            print(str('invalid input'))

    else:
        card_index = random.randint(0,len(client.hand)-1)
        card = client.hand[card_index]
        del client.hand[card_index]
        signature = client.rsa_keys.sign_message(card)
        await sio.emit('card_played', {'status':'playing','table':client.table_id, 'card': card , 'signature': signature})

@sio.on('ask_for_sym_and_bit')
async def ask_for_sym(data):
    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA), data['msg']):
        
        keys = []
        for p in client.players:
            keys.append({'sid': p['sid'], 'sym_key': base64.b64encode(p['sym_key']).decode('utf-8'), 'sym_iv':base64.b64encode(p['sym_iv']).decode('utf-8')})
        msg = 'sending_sym_key'
        signature = client.rsa_keys.sign_message(msg)
        keys = [json.dumps(key) for key in keys]
        await sio.emit('waiting', {'status': msg, 'keys': keys, 'R2': client.R2, 'hand': client.encrypted_hand, 'signature': signature})
    else:
        await sio.emit('error', {'error': 'client couldnt verify croupier in ask_for_sym'})

@sio.on('restart')
async def restart(data):
    await sio.emit('waiting', {})


@sio.on('end_round2')
async def play_next_round(data):
    points = data['points']
    client.hand = []
    print('POINTS:\n')
    print('-----1------2------3------4-----\n')
    print('--  {}  |  {}  |  {}  |  {}  ---\n'.format(points[0],points[1],points[2],points[3]))
    print('--------------------------------\n')
    print('Play next round')
   
    await sio.emit('waiting', {'status':'waiting 4 players'})

###BLOCKCHAIN METHODS###

@sio.on('verify_transaction')
async def verify_transaction(data):
    print('verify transaction', str(data))
    sender = data['sender']
    recipient = data['recipient']
    signature = data['signature']

    player = find_player_by_sid(sender)

    print(str({'sender': data['sender'],\
             'recipient': data['recipient'], \
             'card': data['card'],\
             'signature': player['signature']}))

    if client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(player['public_key']), data['card']):
        client.current_txs.append({'sender': data['sender'],\
             'recipient': data['recipient'], \
             'card': data['card'],\
             'signature': base64.b64encode(data['signature']).decode('utf-8')})
        msg =  'added to pending transactions'
        print(colored('added to pending transactions ', 'blue'))
        await sio.emit('verified_play',{'signature': client.rsa_keys.sign_message(msg), 'msg': msg, 'sender': data['sender']})
    else:
        await sio.emit('error',{'error':'couldnt verify play '})

@sio.on('verify_block')
async def verify_block(data):
    #block = json.loads(data['block'])
    index = data['index']

    transactions = json.loads(data['transactions'])
    last_tx = transactions[-1]
    owner = find_player_by_sid(last_tx['sender'])

    #print(str(client.current_txs))
    
    sender_public_key = owner['public_key']
    
    print(str(base64.b64decode(last_tx['signature'])))
    print(str(client.rsa_keys.load_pub(owner['public_key'])))

    if client.sid == last_tx['sender']:
        blockchain = json.dumps(client.blockchain_copy.get_chain())
        signature = client.rsa_keys.sign_message(blockchain)
        await sio.emit('receive_blockchain_copy',{'chain': blockchain, 'signature': signature})
    elif client.rsa_keys.verify_sig(\
            base64.b64decode(last_tx['signature']),\
            client.rsa_keys.load_pub(owner['public_key']),\
            last_tx['msg']):
        ts = client.blockchain_copy.generate_timestamp()
    #guardar na copia da blockchain do cliente

        print(colored('entrei vou adicionar bloco','red'))

        client.blockchain_copy.add_block({
            'msg': "New block added",
            'index': data['index'],
            'transactions': json.loads(data['transactions']),
            'timestamp': ts,
            'previous_hash': data['previous_hash'],
        })

        if client.blockchain_copy.valid_chain(json.loads(data['chain'])):
            print(str('validou'))
            blockchain = json.dumps(client.blockchain_copy.get_chain())
            signature = client.rsa_keys.sign_message(blockchain)
            await sio.emit('receive_blockchain_copy',{'chain': blockchain, 'signature': signature})
        else:
            await sio.emit('error', {'error':'failed to validate proposed chain'})

    else:   
        await sio.emit('error',{'error':'couldnt verify miner'})
        

@sio.on('end_round')
async def mine(data):
    print(data['block_owner'])
    
    if data['block_owner'] == client.sid \
        and client.rsa_keys.verify_sig(data['signature'], client.rsa_keys.load_pub(client.server_pub_RSA), data['points']+data['winner']+data['block_owner']):
        print(client.sid)
        last_block = client.blockchain_copy.last_block()
        
        #signature = base64.b64encode(signature).decode('utf-8')


        print('data winner', data['winner'])
        if data['winner'] == 'cheating':
            print('entrei aqui ')
            reported_player = data['reported']
            msg = '{} cheated by {}'.format(reported_player, data['cheating_type'])
            signature = client.rsa_keys.sign_message(msg)
            client.current_txs.append({'sender': client.sid,\
            'recipient': client.server_pub_RSA, \
            'msg': msg,\
            'scoreboard': data['points'], \
            'signature': base64.b64encode(signature).decode('utf-8')})

            print(str(signature))
        elif data['winner'] == 'lied':
            reported_player = data['reported']
            reported_by = data['reported_by']
            msg = '{} lied in {}'.format(reported_by, data['cheating_type'])
            signature = client.rsa_keys.sign_message(msg)
            client.current_txs.append({'sender': client.sid,\
            'recipient': client.server_pub_RSA, \
            'msg': msg,\
            'scoreboard': data['points'], \
            'signature': base64.b64encode(signature).decode('utf-8')})
        else:
            msg = 'New block forged'
            signature = client.rsa_keys.sign_message(msg)
            client.current_txs.append({'sender': client.sid,\
                    'recipient': client.server_pub_RSA, \
                    'msg': msg,\
                    'scoreboard': data['points'], \
                    'signature': base64.b64encode(signature).decode('utf-8')})

        # Forge the new Block by adding it to the chain
        previous_hash = client.blockchain_copy.hash(last_block)

        # pp.pprint(client.current_txs[-1])
        print(type(previous_hash))
        print(type(client.current_txs))
        block = client.blockchain_copy.new_block(previous_hash, client.current_txs)
        
        print(type(block))
        #print(str(block))
        client.blockchain_copy.add_block(block)
        #print(str(client.current_txs))
        print(str('deste lado ya'))
        #print(str(json.dumps(client.blockchain_copy.get_chain())),stdrr)
        txs = []
        
        chain = client.blockchain_copy.get_chain()
        response = {
            'msg': msg,
            'index': block['index'],
            'transactions': json.dumps(client.current_txs),
            'previous_hash': block['previous_hash'],
            'chain': json.dumps(chain)
        }      
        await sio.emit('new_block', response)

async def start_server():
    await sio.connect('http://localhost:5000')
    await sio.wait()

if __name__ == '__main__': 

    if len(sys.argv) != 1:
        #jogar com bot
        client.bot = 1
    else: 
        #jogar sem bot
        client.bot = 0

    loop.run_until_complete(start_server())

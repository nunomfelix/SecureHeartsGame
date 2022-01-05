import socketio
from sanic import Sanic
from sanic.response import html

import hashlib
from deck import *
import json
import os
import sys
import names
from termcolor import colored
from cryptography import x509
import base64


from RSA import *
from random import randint, shuffle
from table import Table
import cc
from blockchain.blockchain import Blockchain# sio = socketio.AsyncServer()
# app = socketio.ASGIApp(sio)

sio = socketio.AsyncServer(async_mode='sanic')
app = Sanic()

sio.attach(app)

pass_key = 0
tables = []
key_pair_RSA = RSA('server')


"""
Adicionar padding ao deck
"""
def add_padding_to_deck(deck):
    return [card.decode().rjust(16, '0').encode() for card in deck]


def list_of_table_ids():
    return [table.table_id for table in tables]


def find_table_by_sid(sid):
    for table in tables:
        if sid in table.clients:
            return table

def find_player_by_sid(sid):
    table = find_table_by_sid(sid)
    for p in table.players:
        if p['sid'] == sid:
            return p 

def exists_in_table(sid):
    for table in tables:
        if sid in table.clients:
            return True
    return False

"""
Retorna o estado das mesas ao cliente de estado
DEBUGGING
"""
# @sio.event
# async def state(sid, data):
#     state_dict = dict()
#     for x in tables:
#         state_dict['table '+str(x.table_id)] = {'table state': x.state, 'players': str(
#             x.players), 'clients': str(x.clients)}
#     await sio.emit('state', state_dict, room=sid, namespace='/test')

"""
Cliente conecta-se ao servidor
"""
@sio.event
async def connect(sid, environ):
    # try:
    print('sid {} connected'.format(sid))
        # await sio.emit('connect', room=   sid)
    await sio.emit('connect', {'tables': list_of_table_ids()}, room=sid, namespace='/test')

"""
Retorna as tabelas ao cliente
"""
@sio.on('see_tables')
async def see_tables(sid, data):
    table_list = []

    for x in tables:
        tablePlayers = x.clients
        table_list.append(tablePlayers)

    await sio.emit('choose_table', {'tables': table_list}, room=sid)

@sio.event
async def disconnect(sid):
    print('Disconnect ', sid)

    print('Tables State')
    for table in tables:
        print('{} '.format(table.table_id), table.clients)

        if sid in table.clients:
            table.remove_client(sid)
            table.remove_player(sid)

    # print do estado das mesas
    # ver q cliente desconectou e remover das mesas
    await sio.emit('disconnect', {}, room=sid)



@sio.event
def add_player_to_table(sid, _id):
  sio.enter_room(sid, 'table{}'.format(_id))


@sio.event
def leave_table(sid, _id):
    sio.leave_room(sid, 'table{}'.format(_id))


@sio.on('start')
async def on_start(sid, data):
    print('received data ', str(data))
    #--------------------------------------
    # nesta fase o server manda a sua chave publica RSA, usada para os clients confirmarem a assinatura 
    #--------------------------------------
    try:

        table = tables[int(data['table'])-1]

        if table.num_of_clients() < 4:
            table.encryptAlg.append(data['algoritm'])
            table.add_client(sid)
            add_player_to_table(sid, table.table_id)
            print('adicionei {} na {}'.format(sid, table.table_id))
            # autenticar antes de entrar na room
            msg = 'send credentials pls'

            pub_key = key_pair_RSA.read_pub('server_pubRSA.pem')

            await sio.emit('cc_auth', {'status': msg, 'sid': sid, 'server_public': pub_key , 'signature': key_pair_RSA.sign_message(msg)}, room=sid)
        else:
            table.state = 'table full'
            # mudar para erro
            await sio.emit('enter', {'id': None, 'msg': 'a mesa esta cheia'}, room='table{}'.format(table.table_id))

    except Exception as E:
        print('Exception ', str(E))
        await sio.emit('error', {'error': 'error on start'}, room=sid)  

"""
Verificar autenticação do cliente
"""
@sio.on('verify_auth')
async def verify_auth(sid, data):
    print('verifying authentication')

    citizen_card = cc.CitizenCard()
    cert = citizen_card.getCerts(0)
    sign_verify = citizen_card.verifySign(cert,data['data'],data['signature'])
    cert = base64.b64encode(cert).decode('utf-8')

    #cert = ''
    
    # #table = tables[int(data['table'])-1]

    table = find_table_by_sid(sid)
    table.state = 'verifying auth'


    # verify = citizen_card.verifyChainOfTrust(data['cert'])

    if True and sign_verify == True:
        print('verified chain of trust with success')
        table.players.append(
            {'sid': sid,
            #mudar este name 
            'name': names.get_first_name() + '' + names.get_last_name(),
            'public_key': data['public_key'],
            'data_to_be_signed': data['data'],
            'signature': base64.b64encode(data['signature']).decode('utf-8'),
            'cert': cert,
            'blockchain': ''
            })

        # table.state = 'jogador {} entrou na mesa'.format(sid)

        # Quer dizer que há quatro jogadores autenticados
        print('players ', len(table.players))
        msg = 'you entered the room, waiting for other players'
        # Outros jogadores têm de verificar
        await sio.emit('enter', {'table_id': str(table.table_id), 'sid': sid, 'status': msg, 'signature': key_pair_RSA.sign_message(msg)}, room=sid)
    else:
        print('try again')

"""
Chaves simétricas encriptadas com a chave publica
"""


@sio.on('cipher_channel')
async def pass_to_next(sid, data):
    table = find_table_by_sid(sid)
    if data['status'] == 'pass_deck':
        msg = 'passing_cards'
        await sio.emit('take_cards', {'status': msg, 'message': data['message']}, room='table{}'.format(data['table']))
    elif data['status'] == 'pass_sym_key':
       
        msg = 'sending_sym_key'
        print('estou a passar')
        await sio.emit('receive_sym_key', {'status': msg, 'message': data['message']}, room='table{}'.format(data['table']))
        

@sio.on('finish_pass')
async def finish_pass(sid, data):
    table = find_table_by_sid(sid)
    table.count_ready += 1
    # quatro jogadores já verificaram que o deck está vazio
    if table.count_ready == 4:
        table.count_ready = 0
        msg = 'request to create channel'
        #await sio.emit('create_secure_channel', {'status': msg, 'signature': key_pair_RSA.sign_message(msg)},room='table{}'.format(table.table_id))
        #await sio.emit('send_sym_key', {'status': 'send symmetric key for deck decrypt'}, room='table{}'.format(table.table_id))
        await sio.emit('request_2C',{'status':'Who has the 2C?','players_in_table': table.clients},room='table{}'.format(table.table_id))
    else:
        await sio.emit('check_empty',{'status':'check','players_in_table': table.clients, 'deck': data['deck'], 'valid_cards': data['valid_cards']},room='table{}'.format(table.table_id))


@sio.on('pass_public_channel')
async def pass_public_keys(sid,data):
    table = find_table_by_sid(sid)
    player = next((sub for sub in table.players if sub['sid'] == sid), None)
    if key_pair_RSA.verify_sig(data['signature'], key_pair_RSA.load_pub(player['public_key']), data['key']):
        msg = 'send key'
        await sio.emit('receive_keys_channel', {'status': msg, 'sid': sid, 'key': data['key'],'IV': data['IV'], 'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))


@sio.on('ready_to_start_playing')
async def start_play(sid, data):

    table = find_table_by_sid(sid)
    table.first_player = sid
    plays = [json.dumps(play) for play in table.plays]
    await sio.emit('play_card', {'status': 'request_card','plays': plays, 'cards_played': table.table_cards, 'points': table.score}, room=sid)

@sio.on('verified_play')
async def verified_play(sid,data):

    table = find_table_by_sid(sid)
    
    table.count_verify_tx += 1
    print('verified play')
    player = find_player_by_sid(sid)

    if key_pair_RSA.verify_sig(data['signature'], key_pair_RSA.load_pub(player['public_key']), data['msg']):
        #Sender, recipient, amount
        #table.chain.new_transaction(player['public_key'], key_pair_RSA.read_pub(), 'played ' + card)
        if table.count_verify_tx == 4:
            print('1 carta jogada por {} e verificada por {}'.format(data['sender'],sid))
            table.count_played += 1 
            table.count_verify_tx = 0
            for player in table.players:
                if player['sid'] == data['sender']:
                    name = player['name']

            table.plays[table.clients.index(data['sender'])] = {'name': name, 'card': table.current_card}
            table.current_card = ''
            if table.count_played == 4:
                table.count_played = 0
                table.log_plays.append(table.plays)
                table.plays = [{'name': '', 'card': ''},{'name': '', 'card': ''},{'name': '', 'card': ''},{'name': '', 'card': ''}]

                # next_player tem de ser variavel global
                table.num_plays += 1
                print(colored('check hand winner','red'))
                next_player = table.checkHand_Winner()
                # verificar se o jogo ja acabou, ao final de 13 jogadas
                if table.num_plays == 13:
                    table.num_plays = 0
                    # scores = calc_score()
                    #table.blockchain.new_transaction('', key_pair_RSA.read_pub(), "table score {} winner {}".format(table.score, table.winner))
                    random_player = random.choice(table.players)
                    sid = random_player['sid']

                    print('table.score ',table.score)
                    scoreboard = {table.clients[0]: table.score[0], 
                                   table.clients[1]: table.score[1], 
                                   table.clients[2]: table.score[2],
                                    table.clients[3]: table.score[3]}

                    table.scoreboard = scoreboard


                    print('table.winner ', table.winner)
                    print(sid)
                    if table.check_endGame():
                        print('fim do jogo')
                        msg = 'fim_do_jogo'
                        winner = table.get_winner()
                        signature = key_pair_RSA.sign_message(json.dumps(scoreboard)+table.winner+sid)
                        await sio.emit('end_round', {'status':msg, 'points': json.dumps(scoreboard), 'winner': table.winner, 'block_owner': sid, 'signature' : signature},room="table{}".format(table.table_id))
                        #write last block and write blockchain
                    else:
                        print('fim do round')
                        signature = key_pair_RSA.sign_message(json.dumps(scoreboard)+table.winner+sid)
                        await sio.emit('end_round', {'status':'end_round','points': json.dumps(scoreboard), 'winner': table.winner, 'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))
                else:
                    table.table_cards = ['', '', '', '']  # variavel global no servidor
                    plays = [json.dumps(play) for play in table.plays]
                    await sio.emit('play_card', {'cards_played': table.table_cards,'plays': plays, 'points': table.score}, room=next_player)
    
                #server chooses one user to put the block

                #await sio.emit('end_game', {'points': table.score, 'winner': table.winner}, room='table{}'.format(table.table_id))

            else:
                # next_player_index = table.clients.index(sid) + 1
                next_player_index = table.clients.index(data['sender']) + 1

                if next_player_index > 3:
                    next_player_index = 0
                next_player = table.clients[next_player_index]
                print('next-player ',str(next_player))
                print('nex_player_idx ', str(next_player_index))
                print('table clients ', str(table.clients))
                plays = [json.dumps(play) for play in table.plays]
                await sio.emit('play_card', {'cards_played': table.table_cards,'plays': plays, 'points': table.score}, room=next_player)

@sio.on('card_played')
async def play_next(sid, data):

    table = find_table_by_sid(sid)

    table.table_cards[table.clients.index(sid)] = data['card']
    player = find_player_by_sid(sid)
    print('card_played ', data['signature'])
    if key_pair_RSA.verify_sig(data['signature'], key_pair_RSA.load_pub(player['public_key']), data['card']):
        table.current_card = data['card']
        #Sender, recipient, amount
        #        table.chain.new_transaction(player['public_key'], key_pair_RSA.read_pub(), 'played ' + data['card'])
        await sio.emit('verify_transaction',{'sender': sid, 'recipient': key_pair_RSA.read_pub('server_pubRSA.pem'), 'card': data['card'], 'signature': data['signature']})
    else:
        await sio.emit('error',{'error':'invalid signature from player {}'.format(sid)},room='table{}'.format(table.table_id))

   
"""
Envia aos jogadores o deck encriptado pelos outros
"""
@sio.on('encrypt_deck')
async def receive_deck(sid, data):
    print('sid {} sent encrypted deck'.format(sid))
    table = tables[int(data['table'])-1]
    player = next((sub for sub in table.players if sub['sid'] == sid), None)
    if key_pair_RSA.verify_sig(data['signature'], key_pair_RSA.load_pub(player['public_key']), str(data['deck'])):

        table.count_encrypt += 1
        print('counter ', table.count_encrypt)
        table.encrypt_order.append(sid)
        if table.count_encrypt == 4:
            print('table.count_encrypt==4')
            table.count_encrypt = 0
            
            table.state = 'Encrypted by the table success'
            table.shuffled_deck = data['deck']
            msg = 'create secure channel'
            await sio.emit('create_secure_channel', {'status': msg, 'signature': key_pair_RSA.sign_message(msg)},room='table{}'.format(table.table_id))
            #await sio.emit('take_cards', {'status': msg, 'table': table.table_id, 'deck': table.shuffled_deck, 'valid_cards': 52, 'next_player': b[0], 'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))
        else:
            print('table.clients.index(sid) {}'.format(table.clients.index(sid)))
            print(sid)
            if table.clients.index(sid) + 1 > 3:
                next_player = table.clients[0]
            else:
                next_player = table.clients[table.clients.index(sid) + 1]

            print('NEXT PLAYER ', next_player)
            # next_player = table.clients[table.count_encrypt]
            table.state = 'requiring encrypted deck to {}'.format(next_player)
            print('estou aqui')
            msg = 'need your encrypted deck'
            await sio.emit('request_encrypted_deck', {'status': msg, 'requested_player': next_player,'algoritm': table.sym_algoritm, 'deck': data['deck'], 'players_in_table': table.clients,'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))


# @sio.on('receive_sym_key')
# def decrypt_hand(sid,data):

#     table = tables[int(data['table'])-1]
#     table.count_encrypt+=1

#     if table.count_encrypt == 4:
#         print('ask players for symmetric keys')
#         table.state = 'requesting players symmetric keys'
#         table.shuffled_deck = data['deck']
#         await sio.emit('send_sym_key',{'keys': json.dumps(keys)}, room='table{}'.format(table.table_id))


"""
Chaves simétricas encriptadas com a chave publica
"""


"""
Sala de espera
"""
@sio.on('waiting')
async def client_waiting(sid, data):
    table = find_table_by_sid(sid)
    player = next((sub for sub in table.players if sub['sid'] == sid), None)
    if key_pair_RSA.verify_sig(data['signature'],key_pair_RSA.load_pub(player['public_key']),data['status']):
        if 'bit_commit' in data and data['status'] == 'ready_to_decrypt_hand'+data['bit_commit']:
                msg = 'send keys'
                print(str(data))
                player['bit_commit'] = data['bit_commit']
                player['R1'] = data['R1']
                print('saved {}'.format(player['name']))
        table.waiting_players += 1
        print('client {} waiting'.format(sid))
        if len(table.players) == 4 and table.waiting_players == 4:


            table.waiting_players = 0

            if data['status'] == 'ready_to_encrypt':
                deck = table.deck.get_encoded_deck()
                b = table.clients
                shuffle(b)
                table.state = 'need first player to encrypt deck ({}), sending pub keys'.format(
                    sid)
                print('asking encrypted deck to {}'.format(b[0]))
                msg = 'need your encrypted deck'
                alg = random.choice(table.encryptAlg)
                if alg == 'default':
                    alg = 'AES'
                table.sym_algoritm = alg
              
                await sio.emit('request_encrypted_deck', {'status': msg, 'requested_player': b[0],'algoritm': table.sym_algoritm, 'deck': add_padding_to_deck(deck), 'players_in_table': table.clients, 'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))
            elif data['status'] == 'waiting_4_players':
                msg = 'sending players information'
                await sio.emit('check_player_id',{'status':msg, 'players': json.dumps(table.players
                ), 'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))
            elif data['status'] == 'ready_to_pass_deck':
                print('players are ready to pass')
                msg = 'passing_cards'
                b = table.clients
                shuffle(b)
                await sio.emit('take_cards', {'status': msg, 'table': table.table_id, 'deck': table.shuffled_deck, 'valid_cards': 52, 'next_player': b[0], 'signature': key_pair_RSA.sign_message(msg)}, room=b[0])
            elif 'bit_commit' in data and data['status'] == 'ready_to_decrypt_hand'+data['bit_commit']:
                msg = 'send keys'
                await sio.emit('send_sym_key', {'status': msg, 'signature': key_pair_RSA.sign_message(msg)},room='table{}'.format(table.table_id))
            elif data['status'] == 'have_all_sym_keys':
                print('pedir o 2c')
                msg = 'who_has_the_2C?'
                await sio.emit('request_2C',{'status': msg,'players_in_table': table.clients,'order': table.encrypt_order, 'signature': key_pair_RSA.sign_message(msg)},room='table{}'.format(table.table_id))
        elif data['status'] == 'cheating_played_my_card':
            #o cheater peço a mão encriptada + chaves simétricas
            table.cheating['reported_by'] = sid
            table.cheating['type'] = data['status']
            table.cheating['reported'] = data['check_player']
            table.cheating['card'] = data['card']
            msg = 'asking for sym_key'
            await sio.emit('ask_for_sym_and_bit', {'msg': msg,  'signature': key_pair_RSA.sign_message(msg)}, room=data['check_player'])
        elif data['status'] == 'cheating_played_the_same_card':
            table.cheating['reported_by'] = sid
            table.cheating['type'] = data['status']
           
            table.cheating['reported'] = data['check_player']

            #table.player[data['check_player']]
            random_player = random.choice(table.players)
            sid = random_player['sid']
            scoreboard = json.dumps(table.scoreboard)

            if table.check_cheating():
                print('é verdade')
                signature = key_pair_RSA.sign_message(scoreboard+'cheating'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'cheating', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))
            else:
                print('é mentira')
                signature = key_pair_RSA.sign_message(scoreboard+'lied'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'lied', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))

        elif data['status'] == 'cheating_player_didnt_assist':
            table.cheating['reported_by'] = sid
            table.cheating['type'] = data['status']
            table.cheating['reported'] = data['check_player']
            msg = 'asking for sym_key'
            
            random_player = random.choice(table.players)
            sid = random_player['sid']
            scoreboard = json.dumps(table.scoreboard)

            if table.check_cheating():
                print('é verdade')
                signature = key_pair_RSA.sign_message(scoreboard+'cheating'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'cheating', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))
            else:
                print('e mentira')
                signature = key_pair_RSA.sign_message(scoreboard+'lied'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'lied', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))

        elif data['status'] == 'sending_sym_key':
            
            keys = [json.loads(key) for key in data['keys']]
            
            for player in table.players:
                if player['sid'] == sid:
                    player['encrypt_hand'] = data['hand']
                    player['R2'] = data['R2']
                for key in keys:
                    if player['sid'] == key['sid']:
                        player['sym_key'] = base64.b64decode(key['sym_key'])
                        player['sym_iv'] = base64.b64decode(key['sym_iv'])

            random_player = random.choice(table.players)
            sid = random_player['sid']
            scoreboard = json.dumps(table.scoreboard)

            if table.check_cheating():
                print('é verdade')
                signature = key_pair_RSA.sign_message(scoreboard+'cheating'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'cheating', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))
            else:
                print('e mentira')
                signature = key_pair_RSA.sign_message(scoreboard+'lied'+sid)
                await sio.emit('end_round', {'status':'end_round','points': scoreboard, 'winner': 'lied', 'reported_by':table.cheating['reported_by'] ,'reported': table.cheating['reported'], 'cheating_type': table.cheating['type'],'block_owner': sid, 'signature': signature}, room='table{}'.format(table.table_id))

    else:
        await sio.emit('invalid',{'status':'cant confirm your signature'}, room=sid)

@sio.on('error')
async def error(sid, data):
    print('sid {} with error {}'.format(sid,data['error']))

"""
Blockchain
"""
@sio.on('new_block')
async def new_block(sid, data):
    table = find_table_by_sid(sid)
    print('entrei aqui')
    print(str(data))
    await sio.emit('verify_block', data, room='table{}'.format(table.table_id))

@sio.on('receive_blockchain_copy')
async def receive_blockchain_copy(sid, data): 
    print('receive_blockchain_copy')
    player = find_player_by_sid(sid)
    table = find_table_by_sid(sid)
    if key_pair_RSA.verify_sig(data['signature'], key_pair_RSA.load_pub(player['public_key']), data['chain']):
        player['blockchain'] = json.loads(data['chain'])
        alg = random.choice(table.encryptAlg)
        if alg == 'default':
            alg = 'AES'
        table.sym_algoritm = alg

        count = 0 
        for p in table.players:
            if 'blockchain' in p:
                print("At least one element was found. Do something.")
                count += 1
        
        if count==4:
            print('Received 4 blockchain copies from clients')
            # msg = 'need your encrypted deck'

            # b = table.clients
            # shuffle(b)
            
            # deck = table.deck.get_encoded_deck()
            #await sio.emit('request_encrypted_deck', {'status': 'need your encrypted deck', 'requested_player': b[0],'algoritm': table.sym_algoritm, 'deck': add_padding_to_deck(deck), 'players_in_table': table.clients, 'signature': key_pair_RSA.sign_message(msg)}, room='table{}'.format(table.table_id))
        else:
            print('Não validou')

    else:
        print('chain não foi validada pelo player {}'.format(sid))

# @sio.on('')
# async def waiting_on_consensus(sid, data):

#     table = find_table_by_sid(sid)
#     table.waiting_players+=1
#     if table.waiting_players == 4:

# @sio.on('send_unconfirmed_transactions')
# async def get_unconfirmed_txs(sid, data):
#     table = find.table_by_sid(sid)
#     await sio.emit('get_unconfirmed_transactions', json.dumps(table.chain.get_full_chain()),room=sid)

# @sio.on('get_full_chain')
# async def get_chain(sid, data):
#     table = find_table_by_sid(sid)
#     await sio.emit('receive_chain', {'chain': json.dumps(table.chain), 'length': table.chain.get_chain_size()})

"""
BLOCKCHAIN VIEWER
"""


@app.route('/chain/<table_id:string>/<sid:string>')
async def index(request, table_id, sid):
    print(table_id,sid)
    
    table = tables[int(table_id)-1]
    if exists_in_table(sid):
        player = find_player_by_sid(sid)
        return html(json.dumps(player['blockchain']))
    else:
        return html('Couldn t find player with that sid in table{}'.format(table.table_id))

if __name__ == '__main__':

    if len(sys.argv) != 1:
        n_of_tables = int(sys.argv[1])
    else: 
        n_of_tables = 5
    for x in range(1,n_of_tables+1):
        tables.append(Table(x))

    

    app.run(port=5000,debug=True, access_log=True)


import socketio
import json
import string 
import random
from Crypto.Cipher import DES3
from Crypto import Random
import asyncio
import termcolor

loop = asyncio.get_event_loop()
sio = socketio.AsyncClient()

@sio.on('connect',namespace='/test')
async def connect(*args):
    if args != ():
        print(str(args[0]))
    print('Connected! Receiving game state\n')
    await request_state()

async def request_state():
    await sio.emit('state',{})

@sio.on('get_chains',namespace='/test')
async def get_chains(data):
    print('server state ', str(data))
    print('\n\n')
    
    for k in data:
        print('Table ', k)
        print('State ', data[k]['table state'])
        print('Players ', data[k]['players'])
        
    await sio.sleep(5)
    await request_state()

async def start_server():
    await sio.connect('http://localhost:5000')
    await sio.wait()

if __name__ == '__main__':
    loop.run_until_complete(start_server())
    
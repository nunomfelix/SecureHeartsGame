# Security1920-g20

Secure Hearts Game Implementation using Blockchain

Functionalities implemented:

• Protection (encryption, authentication, etc.) of the
messages exchanged;
• Identification of users in a croupier with their Citizen
Card;
• Set up of sessions between players and a croupier (using
the Citizen Card);
• Set up of sessions between players (using the Citizen
Card);
• Agreement to join a table (using the Citizen Card);
• Deck secure distribution protocol;
• Validation of the cards played during a game by each
player;
• Protest against cheating;
• Possibility of cheating;
• Game accounting agreement;
• Blockchain for accounting;


## Installation


Install swig
sudo apt install swig

Install requirements
```bash
pip3 install -r requirements.txt
```

## Run Client and Server

Server

```bash
python3 wsserver.py [number_of_croupiers]
```

Client

```bash
python3 wsclient.py
```

State Client for Debugging

```bash
python3 clientstate.py
```

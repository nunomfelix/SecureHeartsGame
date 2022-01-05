#!/bin/bash

shopt -s nocasematch
read -p " Execute script? (y/n): " response
if [[ $response == y ]]; then
    printf " Loading....\\n"
    for ((x = 0; x<4; x++)); do
        printf " Open %s Terminal\\n" $x
        gnome-terminal &
        cd /home/nmf/Desktop/security1920-g20
        chmod +x wsclient.py
        python3 wsclient.py
    done
fi
shopt -u nocasematch
#!/bin/bash

# gcc relay.c ../Shared/* -o relay -lcrypto -lminiupnpc -pthread -D_GNU_SOURCE -I/usr/include/openssl -I/usr/include/miniupnpc -Wall

sshpass -p 'raspberry' scp Client/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Shared

sshpass -p 'raspberry' scp Client/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Shared

sshpass -p 'raspberry' scp Client/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Shared

#!/bin/bash

sshpass -p 'raspberry' scp Client/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.200:./Documents/Projects/Tricklechat_C/Shared

sshpass -p 'raspberry' scp Client/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.201:./Documents/Projects/Tricklechat_C/Shared

sshpass -p 'raspberry' scp Client/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Client
sshpass -p 'raspberry' scp Relay/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Relay
sshpass -p 'raspberry' scp Shared/* pi@10.10.6.202:./Documents/Projects/Tricklechat_C/Shared
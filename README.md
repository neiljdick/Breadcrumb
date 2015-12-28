# Breadcrumb
Breadcrumb is an application which allows users to send text based messages across the internet.
The manner in which message transactions to occur will be such that:

* User Discovery - Chat initialization occurs in a secure manner, immune to MITM attack
* End-to-end encrypted - Message plaintext is only available to the sender and intended recipient
* Forward secrecy - Key compromise does not allow previous messages to be decrypted
* Internal Metadata Leaking - User metadata is hidden from the Breadcrumb infrastructure
* External Metadata Leaking - User metadata is hidden from an adversary capable of observing network traffic

## Documentation
Available within the directory Meta/Design/Documentation or [online](https://github.com/chaywood7/Breadcrumb/blob/master/Meta/Design/Documentation/breadcrumb.pdf).

## Dependencies
* OpenSSL - https://www.openssl.org
* Miniupnpc - http://miniupnp.tuxfamily.org/

## Getting Started
#### Install Dependencies
```
sudo apt-get install libssl-dev
sudo apt-get install libminiupnpc-dev
```
#### Get Breadcrumb
```
git clone https://github.com/chaywood7/Breadcrumb
```
#### Compile Client
```
cd Breadcrumb/Client/
make
```
#### Compile Node
```
cd Breadcrumb/Node/
make
```
#### Starting a Client
```
./client USER ID PORT [CLIENT ONE {Y/N}]
```
The command line arguments are defined as follows:
* USER ID - An identifier to connect to other clients (only available in test mode).
* PORT - Port number used for outgoing connections which carry message packets. Must be greater than 16384.
* CLIENT ONE {Y/N} - Optional argument only valid when the client is compiled in test mode. 
This switch (set by 'y' or 'Y', unset if not present or anything else) controls the entry node of the client and
other conversation participant (see function 'setup test mode conversation').

#### Starting a Node
```
./node NODE ID PORT [LOGGING INTERVAL]
```
The command line arguments are defined as such:
* NODE ID - Used by clients as part of the route denitions (see section 5.3 'Packet Types').
* PORT - The port number on which the Node listens for incoming connections carrying message packets. Must be greater than 16384.
* LOGGING INTERVAL - An integer which sets the interval between metadata logging events as dened by the 'logging interval' enum present in 'node.h'.

## Test Mode
Currently the Breadcrumb infrastructure supports clients communicating via a LAN, provided 'test mode' is enabled and 
the nodes as defined in the function 'setup_test_mode_conversation' (client.c) are present. To enable 'test mode' ensure
the following switch is uncommented in 'client.c':
```
#define TEST_MODE
```
Ensure that the Nodes as define in 'setup_test_mode_conversation' are present (alternatively modify the function to reflect 
your LAN setup):
```c
	strcpy(ci_out->ri_pool[0].node_ip, "10.10.6.200");
	strcpy(ci_out->ri_pool[1].node_ip, "10.10.6.201");
	strcpy(ci_out->ri_pool[2].node_ip, "10.10.6.202");
	strcpy(ci_out->ri_pool[3].node_ip, "10.10.6.220");
	ci_out->ri_pool[0].node_port = 22222;
	ci_out->ri_pool[1].node_port = 22222;
	ci_out->ri_pool[2].node_port = 22222;
	ci_out->ri_pool[3].node_port = 22222;
	ci_out->ri_pool[0].is_active = 1;
	ci_out->ri_pool[1].is_active = 1;
	ci_out->ri_pool[2].is_active = 1;
	ci_out->ri_pool[3].is_active = 1;
	ci_out->ri_pool[0].is_responsive = 1;
	ci_out->ri_pool[1].is_responsive = 1;
	ci_out->ri_pool[2].is_responsive = 1;
	ci_out->ri_pool[3].is_responsive = 1;
	ci_out->conversation_valid = 1;
```

## Sample Output
### Clients

#### Client 1 (10.10.6.100)
```
./client pink 22234 y
> /connect floyd
-!- Initializing conversation....done
-!- Initializing networking....done
floyd/> Hello... is there anybody out there?
me/> *nods*
me/> I can hear you
me/> /exit
```

#### Client 2 (10.10.6.101)
```
./client floyd 47223 n
> /connect pink
-!- Initializing conversation....done
-!- Initializing networking....done
me/> Hello... is there anybody out there?
pink/> *nods*
pink/> I can hear you
me/> /exit
```

### Nodes

#### Node 1 (10.10.6.200)
```
./node node1 22222
[MAIN THREAD] Node id=46d1b83a686f8150c353e6f1edc24c9cc23775305edf25560e61a776747ca176
[MAIN THREAD] Node program begin
Enter private key password: ***
[MAIN THREAD] Initializing key store heaps..........done
[ID CACHE CLIENT THREAD 0xb38ff460] Received id cache data
[MSG CLIENT THREAD 0xb38ff460] Received routing packet, next ip = 10.10.6.220, port = 22222
[MSG CLIENT THREAD 0xb2eff460] Received routing packet, next ip = 10.10.6.201, port = 22222
[ID CACHE CLIENT THREAD 0xb2eff460] Received id cache data
[MSG CLIENT THREAD 0xb2eff460] Received routing packet, next ip = 10.10.6.201, port = 22223
[MSG CLIENT THREAD 0xb2eff460] Received routing packet, next ip = 10.10.6.202, port = 22223
...
```

#### Node 2 (10.10.6.201)
```
./node node2 22222
[MAIN THREAD] Node id=cfff71ecbfb28d3f9e3dd64b789c5e1e0853bcdeb4458595ce5904456bfdb8ba
[MAIN THREAD] Node program begin
Enter private key password: ***
[MAIN THREAD] Initializing key store heaps........done
[ID CACHE CLIENT THREAD 0x6eeff460] Received id cache data
[MSG CLIENT THREAD 0x6eeff460] Received routing packet, next ip = 10.10.6.220, port = 22223
[MSG CLIENT THREAD 0x6eeff460] Received routing packet, next ip = 10.10.6.202, port = 22223
[MSG CLIENT THREAD 0x6eeff460] Received routing packet, next ip = 10.10.6.200, port = 22223
...
```

#### Node 3 (10.10.6.202)
```
./node node3 22222
[MAIN THREAD] Node id=eebc37bab3ceb43cf3b01e8ef434201bbf3bafd9f9f79ecdc0860f9041a69a2b
[MAIN THREAD] Node program begin
Enter private key password: ***
[MAIN THREAD] Initializing key store heaps..........done
[ID CACHE CLIENT THREAD 0xb37ff460] Received id cache data
[MSG CLIENT THREAD 0xb37ff460] Received routing packet, next ip = 10.10.6.200, port = 22222
[MSG CLIENT THREAD 0xb37ff460] Received non-route packet, type = DUMMY_PACKET_W_RETURN_ROUTE. Next ip = 10.10.6.220, port = 22222
[ID CACHE CLIENT THREAD 0xb37ff460] Received id cache data
[MSG CLIENT THREAD 0xb37ff460] Received routing packet, next ip = 10.10.6.201, port = 22222
[MSG CLIENT THREAD 0xb2dff460] Received routing packet, next ip = 10.10.6.220, port = 22222
[MSG CLIENT THREAD 0xb2dff460] Received routing packet, next ip = 10.10.6.220, port = 22222
...
```

#### Node 3 (10.10.6.220)
```
./node node4 22222
[MAIN THREAD] Node id=1f991df1fc18f1c7ea77487cad9fd326c14241d5b1133f872a570b633e5d17fe
[MAIN THREAD] Node program begin
Enter private key password: ***
[MAIN THREAD] Initializing key store heaps......................................done
[ID CACHE CLIENT THREAD 0xc3fff700] Received id cache data
[MSG CLIENT THREAD 0xc3fff700] Received non-route packet, type = DUMMY_PACKET_W_RETURN_ROUTE. Next ip = 10.10.6.202, port = 22222
[MSG CLIENT THREAD 0xc3fff700] Received routing packet, next ip = 10.10.6.201, port = 22222
[MSG CLIENT THREAD 0xc3fff700] Received return route packet, onion_r1 = 0xe5e, onion_r2 = 0xa633, client_id = 0xaf343c52, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.202, onion_r1_port = 22222, onion_r1_ip = 10.10.6.202, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[MSG CLIENT THREAD 0xc3fff700] Received return route packet, onion_r1 = 0xe5e, onion_r2 = 0xa633, client_id = 0xaf343c52, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.202, onion_r1_port = 22222, onion_r1_ip = 10.10.6.202, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[ID CACHE CLIENT THREAD 0xc3fff700] Received id cache data
[MSG CLIENT THREAD 0xc35e8700] Received return route packet, onion_r1 = 0xa633, onion_r2 = 0xe5e, client_id = 0xaf343c52, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.200, onion_r1_port = 22222, onion_r1_ip = 10.10.6.200, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[MSG CLIENT THREAD 0xc35e8700] Received message packet, onion_r1 = 0x9cb2, order = 0x0, client_id = 0xaf343c52, conversation_id = 0xc98bd69e. Storing packet
[MSG CLIENT THREAD 0xc35e8700] Received return route packet, onion_r1 = 0xbdf1, onion_r2 = 0x9cb2, client_id = 0x66bfeacc, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.201, onion_r1_port = 22222, onion_r1_ip = 10.10.6.201, onion_r2_port = 22222. Searching for matching message packet
Found matching onion, 9cb2
[MSG CLIENT THREAD 0xc35e8700] Received return route packet, onion_r1 = 0xe5e, onion_r2 = 0xa633, client_id = 0xaf343c52, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.202, onion_r1_port = 22222, onion_r1_ip = 10.10.6.202, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[MSG CLIENT THREAD 0xc35e8700] Received return route packet, onion_r1 = 0xbdf1, onion_r2 = 0x9cb2, client_id = 0x66bfeacc, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.201, onion_r1_port = 22222, onion_r1_ip = 10.10.6.201, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[MSG CLIENT THREAD 0xc35e8700] Received non-route packet, type = DUMMY_PACKET_NO_RETURN_ROUTE. Dropping packet
[MSG CLIENT THREAD 0xc2de7700] Received message packet, onion_r1 = 0xa633, order = 0x0, client_id = 0x66bfeacc, conversation_id = 0xc98bd69e. Storing packet
[MSG CLIENT THREAD 0xc2de7700] Received return route packet, onion_r1 = 0xa633, onion_r2 = 0xe5e, client_id = 0xaf343c52, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.200, onion_r1_port = 22222, onion_r1_ip = 10.10.6.200, onion_r2_port = 22222. Searching for matching message packet
Found matching onion, a633
[MSG CLIENT THREAD 0xc2de7700] Received return route packet, onion_r1 = 0xbdf1, onion_r2 = 0x9cb2, client_id = 0x66bfeacc, conversation_id = 0xc98bd69e onion_r1_ip = 10.10.6.201, onion_r1_port = 22222, onion_r1_ip = 10.10.6.201, onion_r2_port = 22222. Searching for matching message packet
Failed to find matching message packet
[MSG CLIENT THREAD 0xc3fff700] Received routing packet, next ip = 10.10.6.202, port = 22222
...
```
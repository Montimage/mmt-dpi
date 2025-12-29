# NDN test cases

## How to generate NDN protocol trace file

Traces de protocole NDN (version NFD 2.0) capturées avec Wireshark et avec l’outil NDNDUMP, pour NDN configuré pour tourner au-dessus de IP et pour NDN configuré pour tourner directement au-dessus d’Ethernet (layer 2).

### Configuration

2 machines reliées sur un hub.

```
Host1 : 192.168.1.12
Host2 : 192.168.1.11
```

Pile NDN version FD2.0 installée et configurée
Test avec appli ChronoChat (fourni par NDN)

### Scénario pour NDN/IP

**Pour Wireshark** : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de AAAAAAAAAAAAAAAAA dans un sens, puis envoie de ZZZZZZZZZZZZZZZZZ dans l’autre sens.

**Pour NDNDUMP** : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de XXXXXXXXXXXXXXXXXX dans un sens, puis envoie de WWWWWWWWWWWW dans l’autre sens.

### Scénario pour NDN/Ethernet

**Pour Wireshark** : échanges entres les 2 machines : envoi de HELLLLLLLLLLLLLLLLLLLLLLLOOOO  dans un sens, puis envoie de YEEEEEEEEEEEEEEEESSSSSSSSSSS dans l’autre sens.

## Data set

There are 2 trace files to test

* `ndn_TCP_ChronoChat.pcapng`: NDN over TCP

* `ndn_ETH_ChronoChat.pcapng`: NDN over Ethernet

## Test case

Each test case will correspond with a trace file.

### Test case possible

* NDN protocol over TCP

* NDN protocol over Ethernet

### How to test a trace file

* `ndn_extraction.c` -> Extract attributes of NDN protocol by using `packet_handler`, `register_extraction_attribute` and `get_attribute_extracted_data`.

-> Expect to see all correct value of all registered attributes

* `extract_all.c` -> Extract all attributes of all protocol stack of packet: extract everything

-> Expect to see all attributes of NDN protocol of every NDN packet i.e ndn.p_payload, ndn.p_data,....

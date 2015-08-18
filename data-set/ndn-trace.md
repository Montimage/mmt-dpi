# How to generate NDN protocol trace file

Traces de protocole NDN (version NFD 2.0) capturées avec Wireshark et avec l’outil NDNDUMP, pour NDN configuré pour tourner au-dessus de IP et pour NDN configuré pour tourner directement au-dessus d’Ethernet (layer 2).

## Configuration :

2 machines reliées sur un hub.

```
Host1 : 192.168.1.12
Host2 : 192.168.1.11
```

Pile NDN version FD2.0 installée et configurée
Test avec appli ChronoChat (fourni par NDN)

## Scénario pour NDN/IP:

Pour Wireshark : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de AAAAAAAAAAAAAAAAA dans un sens, puis envoie de ZZZZZZZZZZZZZZZZZ dans l’autre sens.
Pour NDNDUMP : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de XXXXXXXXXXXXXXXXXX dans un sens, puis envoie de WWWWWWWWWWWW dans l’autre sens.

## Scénario pour NDN/Ethernet:

Pour Wireshark : échanges entres les 2 machines : envoi de HELLLLLLLLLLLLLLLLLLLLLLLOOOO  dans un sens, puis envoie de YEEEEEEEEEEEEEEEESSSSSSSSSSS dans l’autre sens.

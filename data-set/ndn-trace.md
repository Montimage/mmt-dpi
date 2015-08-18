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

**Pour Wireshark** : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de AAAAAAAAAAAAAAAAA dans un sens, puis envoie de ZZZZZZZZZZZZZZZZZ dans l’autre sens.

**Pour NDNDUMP** : échanges entres les 2 machines : phrase dans un sens puis une autre dans l’autre sens puis envoi de XXXXXXXXXXXXXXXXXX dans un sens, puis envoie de WWWWWWWWWWWW dans l’autre sens.

## Scénario pour NDN/Ethernet:

**Pour Wireshark** : échanges entres les 2 machines : envoi de HELLLLLLLLLLLLLLLLLLLLLLLOOOO  dans un sens, puis envoie de YEEEEEEEEEEEEEEEESSSSSSSSSSS dans l’autre sens.

## Understand NDN data format

Each NDN packet is encoded in a Type-Length-Value (TLV) format. You can check [Type-Length-Value (TLV) Encoding](http://named-data.net/doc/ndn-tlv/tlv.html) and [Type value assignment](http://named-data.net/doc/ndn-tlv/types.html)

### Interest packet

We will parse an interest packet:

```
05:3b:07:2b:08:08:6c:6f:63:61:6c:68:6f:70:08:0c:6e:64:6e:2d:61:75:74:6f:63:6f:6e:66:08:11:72:6f:75:74:61:62:6c:65:2d:70:72:65:66:69:78:65:73:09:02:12:00:0a:04:2c:f3:00:6e:0c:02:03:e8
```
_Analysis_
 
**Packet type**

* T-**05**: interest packet

* L-**3b**: 59 (decimal value) -> The NDN packet len is 59 octets, the value after this

* V-
	**Common fields**

	* T-**07**: Name

	* L-**2b**: 43 -> The name of NDN packet has the lenght 43 octets, the value after this
	
	* V-
		* T-**08**: NameComponent
		
		* L-**08**: 8 -> The length of NameComponent is 8 octets
		
		* V-**6c:6f:63:61:6c:68:6f:70**: localhop
		

		* T-**08**: NameComponent
		
		* L-**0c**: 12 -> The length of NameComponent is 12 octets
		
		* V-**6e:64:6e:2d:61:75:74:6f:63:6f:6e:66**: ndn-autoconf
		
		
		* T-**08**: NameComponent
		
		* L-**11**: 17 -> The length of NameComponent is 17 octets
		
		* V-**72:6f:75:74:61:62:6c:65:2d:70:72:65:66:69:78:65:73**: routable-prefixes
		
	**Interest packet**
	
	* T-**09**: Selectors
		
	* L-**02**: 2 -> The length of Selectors is 2 octets
		
	* V-
		* T-**12**: MustBeFresh 
		
		* L-**00**: 0 -> The length of this field is 0 octet
		

	* T-**0a**: Nonce
	
	* T-**04**: 4-> The length of this field is 4 octets
	
	* V-**2c:f3:00:6e:
	

	* T-**0c**: InterestLifetime
		
	* L-**02**: 2 -> The length of this field is 2 octets
	
	* V-**03:e8**: 1000 seconds
		
	
	 
	 


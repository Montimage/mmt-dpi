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

<p>05:3b:07:2b:08:08:6c:6f:63:61:6c:68:6f:70:08:0c:6e:64:6e:2d:61:75:74:6f:63:6f:6e:66:08:11:72:6f:75:74:61:62:6c:65:2d:70:72:65:66:69:78:65:73:09:02:12:00:0a:04:2c:f3:00:6e:0c:02:03:e8</p>

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
	
	
### Data packet

We will parse a NDN data packet:


<p>06:fd:01:f4:07:45:08:03:6e:64:6e:08:09:62:72:6f:61:64:63:61:73:74:08:0a:43:68:72:6f:6e:6f:43:68:61:74:08:05:74:65:73:74:31:08:20:e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55:14:04:19:02:03:e8:15:62:80:60:81:5e:07:59:08:07:70:72:69:76:61:74:65:08:05:6c:6f:63:61:6c:08:02:f0:2e:08:17:63:68:72:6f:6e:6f:63:68:61:74:2d:74:6d:70:2d:69:64:65:6e:74:69:74:79:08:08:36:65:36:65:30:63:64:65:08:0f:43:48:52:4f:4e:4f:43:48:41:54:2d:44:41:54:41:08:05:74:65:73:74:31:08:08:00:00:01:4a:ed:bf:e5:04:82:01:01:16:3d:1b:01:01:1c:38:07:36:08:09:6c:6f:63:61:6c:68:6f:73:74:08:08:6f:70:65:72:61:74:6f:72:08:03:4b:45:59:08:11:6b:73:6b:2d:31:34:32:31:31:34:30:31:37:30:37:33:34:08:07:49:44:2d:43:45:52:54:17:fd:01:00:5b:d6:58:71:e2:3c:3c:3f:0d:4d:ba:4b:7c:87:b6:21:3b:eb:9f:51:c8:85:2a:89:dd:fc:8a:8c:71:fb:aa:ff:26:f8:4f:34:f0:f8:44:6c:86:e5:d8:89:7d:4e:23:59:22:70:d0:3f:62:e0:ec:9e:05:98:3e:fe:98:ff:58:90:78:59:a6:c1:16:d6:90:3c:01:16:d8:15:1f:23:0a:bc:fa:c6:5c:bf:cf:9f:d4:83:0f:fe:a6:71:57:29:ad:ed:fb:eb:0c:91:8c:53:be:67:38:5b:50:ea:63:0d:2f:68:77:fc:b4:ae:03:d5:a8:57:02:4a:06:21:fa:48:24:82:41:9e:a7:d7:ea:96:c4:d9:76:d0:b2:fa:4b:08:39:d9:9c:a2:dc:ff:96:dd:91:be:b8:da:61:84:97:dc:0d:a0:3b:24:e2:4e:73:4c:cf:35:9a:cb:b9:6e:93:d6:cf:3f:72:79:85:23:41:26:95:03:fe:15:f3:9b:31:c9:d3:fa:9a:d4:cb:bd:3f:9c:60:bd:d0:fd:1d:f7:85:f4:41:fe:14:75:f8:55:d9:23:30:43:77:c0:ff:2f:09:c5:43:3f:8c:dd:6b:ad:7a:0e:2e:63:14:ba:df:d2:a2:1b:49:de:6c:c9:bc:9a:c1:7e:a6:a9:0e:f8:0a:fd:ae:a3:d7:5d</p>

_Analysis_
 
**Packet type**

* T-**06**: data packet

* L-**fd**: 253 (decimal value) -> 2 octets ([see why?](http://named-data.net/doc/ndn-tlv/tlv.html#variable-size-encoding-for-type-t-and-length-l)) 

	-> L-**01:f4** 500 -> The NDN packet len is 500 octets, the value after this

* V-
	**Common fields**

	* T-**07**: Name

	* L-**45**: 69 -> The name of NDN packet has the lenght 69 octets, the value after this
	
	* V-
		* T-**08**: NameComponent
		
		* L-**03**: 3 -> The length of NameComponent is 3 octets
		
		* V-**6e:64:6e**: ndn
		

		* T-**08**: NameComponent
		
		* L-**09**: 9 -> The length of NameComponent is 9 octets
		
		* V-**62:72:6f:61:64:63:61:73:74**: broadcast
		
		
		* T-**08**: NameComponent
		
		* L-**0a**: 10 -> The length of NameComponent is 10 octets
		
		* V-**43:68:72:6f:6e:6f:43:68:61:74**: ChronoChat
		
		
		* T-**08**: NameComponent
		
		* L-**05**: 5 -> The length of NameComponent is 5 octets
		
		* V-**74:65:73:74:31**: test1
		
		
		* T-**08**: NameComponent
		
		* L-**20**: 32 -> The length of NameComponent is 32 octets
		
		* V-**e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55**: ã°ÄBüûôÈo¹$'®AädL¤xR¸U
		
	**Data packet**
	* T-**14**: MetaInfo
	
	* L-**04**: 4 octets
	
	* V-
		* T-**19**: FreshnessPeriod 
		
		* L-**02**: 2 octets
		
		* V-**03:e8**: 
	
	
	* T-**15**: Content
	
	* L-**62**: 98 octets
	
	* V-: <p>80:60:81:5e:07:59:08:07:70:72:69:76:61:74:65:08:05:6c:6f:63:61:6c:08:02:f0:2e:08:17:63:68:72:6f:6e:6f:63:68:61:74:2d:74:6d:70:2d:69:64:65:6e:74:69:74:79:08:08:36:65:36:65:30:63:64:65:08:0f:43:48:52:4f:4e:4f:43:48:41:54:2d:44:41:54:41:08:05:74:65:73:74:31:08:08:00:00:01:4a:ed:bf:e5:04:82:01:01 -> `^Yprivatelocalð.chronochat-tmp-identity6e6e0cdeCHRONOCHAT-DATAtest1Jí¿å</p>
	
	
	* T-**16**: SignatureInfo
	
	* L-**3d**: 61 octets
	
	* V-
		* T-**1b**: SignatureType 
		
		* L-**01**: 1 octet
		
		* V-**01**: SignatureSha256WithRsa ([see why](http://named-data.net/doc/ndn-tlv/signature.html#signaturetype))
		
		
		* T-**1c**: KeyLocator
		
		* L-**38**: 56 octets
		
		* V-:<p>07:36:08:09:6c:6f:63:61:6c:68:6f:73:74:08:08:6f:70:65:72:61:74:6f:72:08:03:4b:45:59:08:11:6b:73:6b:2d:31:34:32:31:31:34:30:31:37:30:37:33:34:08:07:49:44:2d:43:45:52:54 -> 6	localhostoperatorKEYksk-1421140170734ID-CERT</p>
		
		
	* T-**17**: SignatureValue
	
	* L-**fd**: 253 -> 2 octets for length-> L-**01:00**: 256 octets
	
	* V-:<p>5b:d6:58:71:e2:3c:3c:3f:0d:4d:ba:4b:7c:87:b6:21:3b:eb:9f:51:c8:85:2a:89:dd:fc:8a:8c:71:fb:aa:ff:26:f8:4f:34:f0:f8:44:6c:86:e5:d8:89:7d:4e:23:59:22:70:d0:3f:62:e0:ec:9e:05:98:3e:fe:98:ff:58:90:78:59:a6:c1:16:d6:90:3c:01:16:d8:15:1f:23:0a:bc:fa:c6:5c:bf:cf:9f:d4:83:0f:fe:a6:71:57:29:ad:ed:fb:eb:0c:91:8c:53:be:67:38:5b:50:ea:63:0d:2f:68:77:fc:b4:ae:03:d5:a8:57:02:4a:06:21:fa:48:24:82:41:9e:a7:d7:ea:96:c4:d9:76:d0:b2:fa:4b:08:39:d9:9c:a2:dc:ff:96:dd:91:be:b8:da:61:84:97:dc:0d:a0:3b:24:e2:4e:73:4c:cf:35:9a:cb:b9:6e:93:d6:cf:3f:72:79:85:23:41:26:95:03:fe:15:f3:9b:31:c9:d3:fa:9a:d4:cb:bd:3f:9c:60:bd:d0:fd:1d:f7:85:f4:41:fe:14:75:f8:55:d9:23:30:43:77:c0:ff:2f:09:c5:43:3f:8c:dd:6b:ad:7a:0e:2e:63:14:ba:df:d2:a2:1b:49:de:6c:c9:bc:9a:c1:7e:a6:a9:0e:f8:0a:fd:ae:a3:d7:5d -> ... </p>
		
		
### How to classify NDN packet?

		
	
	 
	 


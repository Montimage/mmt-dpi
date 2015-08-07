MMT-Extract library

MMT-Extract is a software C library designed to extract data attributes from network packets, server logs, and from structured events in general, in order to make them available for analysis.

# Installing MMT-Extract

Before installing MMT-Extract, you need to install some required packages:

$ sudo apt-get install libxml2-dev libpcap-dev make

Then you can install MMT-Extract by following command:

$ sudo make install

You also can uninstall MMT-Extract by following command:

$ sudo make uninstall

# Using MMT-Extract

You can go to examples/ folder to test some examples of using MMT-Extract library

## proto_attributes_iterator.c
This example is intended to provide the list of available protocols and for each protocol, the list of its attributes.

Compile:

$ gcc -o proto_attributes_iterator proto_attributes_iterator.c -lmmt_core -ldl

Execute:
$ ./proto_attributes_iterator

## extract_all.c
This example is intended to extract everything that means all the attributes of all registed protocols will be registered for extraction. When a packet is processed, the attributes found in the packet will be printed out.

Compile:

$ gcc -g -o extract_all extract_all.c -lmmt_core -ldl -lpcap

Execute:
Extract from a .pcap file:

$ ./extract_all -t pcapfile.pcap

Extract from live stream:

$ sudo ./extract_all -i eth0

You can check more our API document at http://mmtlib.montimage.com/api


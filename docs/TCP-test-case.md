# TCP protocol test case

To test the TCP plugin, we need to get some trace files for testing TCP protocol

## Get `.pcap` file

To get a pcap file to test offline, follow the process:

* Prepare the test script (choose a test case)

* Open Wireshark application

* Start a new capturing

* Filter the traffic by `tcp`

* Stop the capturing and save the captured packets in Wireshark

Using this trace file to test TCP plugin

## Test case

Each test case will correspond with a trace file.

### What do we need to monitor

* TCP session status: OPEN (3 handshakes), ESTABLISHED (After handshaking), CLOSED(Terminate)

* TCP data stream:

* Order

* Retransmission of lost packets

* Error-free data transfer

* Flow control

* Congestion control

### Test case possible

* TCP normal: All the packet in order and there is no retransmission ....

* TCP out of order

* TCP retransmission

### How to test a trace file

* `tcp_extraction.c` -> Extract attributes of TCP protocol by using `packet_handler`, `register_extraction_attribute` and `get_attribute_extracted_data`.

-> Expect to see all correct value of all registered attributes

* `extract_all.c` -> Extract all attributes of all protocol stack of packet: extract everything

-> Expect to see all attributes of TCP protocol of every TCP packet i.e tcp.p_payload, tcp.p_data,....

* `tcp_reconstruct.c` -> Reconstruct the payload of TCP packet

-> Expect to have the file which was transferred by TCP protocol. Especially for this test, some type of file should be tested: `text`, `.pdf`, `image`, `audio`, `bin`, `compressed`, `video`.

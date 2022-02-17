# FTP protocol test case

To test the FTP plugin, we need to setup the environment for testing FTP protocol

## Install and config a FTP Server

[How to install and config a FTP Server on ubuntu](https://help.ubuntu.com/lts/serverguide/ftp-server.html)

## Working with `ftp` in terminal

[Basic FTP Commands](https://www.cs.colostate.edu/helpdocs/ftp.html)


## Get `.pcap` file

To get a pcap file to test offline, follow the process:

* Prepare the test script (choose a test case)

* Start FTP Server (If it is not started yet)

* Open terminal

* Open Wireshark application 

* Start a new capturing

* Filter the traffic by IP address of FTP Server

* Access to FTP Server and follow the test script

* After finishing the test script -> `quit` FTP client

* Stop the capturing and save the captured packets in Wireshark

Using this trace file to test FTP plugin

## Test case

Each test case will correspond with a trace file.

### What do we need to monitor

* Control connection state

* Data transfer processing

### Test case possible:

* Download a single file - **Passed**

* Download multiple files - **Passed**

* Upload a single file - **Passed**

* Upload multiples files - **Passed**

* Upload/Download mixture - **Passed**

* Download files by using browser - **Passed**

* More than 1 ftp control session on a trace file - **Passed**

### How to test a trace file

* `ftp_extraction.c` -> Extract attributes of FTP protocol by using `packet_handler`, `register_extraction_attribute` and `get_attribute_extracted_data`.

-> Expect to see all correct value of all registered attributes - **Passed**

* `extract_all.c` -> Extract all attributes of all protocol stack of packet: extract everything

-> Expect to see all attributes of FTP protocol of every FTP packet i.e ftp.p_payload, ftp.p_data,.... - **Passed**

* `ftp_reconstruct_body.c` -> Reconstruct the file which was transferred by FTP protocol.

-> Expect to have the file which was transferred by FTP protocol. Especially for this test, some type of file should be tested: `text`, `.pdf`, `image`, `audio`, `bin`, `compressed`, `video`. - **Passed**
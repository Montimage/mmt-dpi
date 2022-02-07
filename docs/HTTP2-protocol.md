# HTTP2 protocol

## Overview

** Working branch: ** feature/http2

** Started date: ** 03/04/2017

** Deadline: ** 05/04/2017 

** Developer: ** @luongnv89 

** Probe example **: extract all attributes value ,... more detail after studying 

## List of tasks

* Study about protocol -> understand packet format specification/ how to classify protocol

* Create data struct for extracting protocol attributes

* Study some open-source library (if it exists) to see how do they do

* Implement classify HTTP2 packet

* Implement parse HTTP2 packet data

* Test HTTP2 plugin

* Merge to MMT-SDK


## HTTP2 experiments

Install HTTP2 : [https://github.com/nghttp2/nghttp2](https://github.com/nghttp2/nghttp2)


## HTTP2 identification

- Over TCP
- http and https
- default port: 80 (http) and 443 (https)
- String `h2` identifies the protocol where HTTP/2 uses TLS
- String `h2c` identifies the protocol where HTTP/2 is run over cleartext TCP - used in the HTTP/1.1 Upgrade header field

### HTTP/2 for 'http'

Request

```
GET / HTTP/1.1
Host: server.example.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>

```


Response from a non supported HTTP/2 server:

```
HTTP/1.1 200 OK
Content-Length: 243
Content-Type: text/html

...

```


Response from a supported HTTP/2 server with `101 Switching Protocols`:

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c

[ HTTP/2 connection ...
```




## HTTP2 frame format

References: [HTTP/2](http://httpwg.org/specs/rfc7540.html#FramingLayer)

```
 +-----------------------------------------------+
 |                 Length (24)                   |
 +---------------+---------------+---------------+
 |   Type (8)    |   Flags (8)   |
 +-+-------------+---------------+-------------------------------+
 |R|                 Stream Identifier (31)                      |
 +=+=============================================================+
 |                   Frame Payload (0...)                      ...
 +---------------------------------------------------------------+
```

**Length**: The length of the frame payload expressed as an unsigned 24-bit integer. Values greater than 214 (16,384) MUST NOT be sent unless the receiver has set a larger value for `SETTINGS_MAX_FRAME_SIZE`.

The 9 octets of the frame header are not included in this value.

**Type**: Type of the frame, determines the format and semantics of the frame. Implementations MUST ignore and discard any frame that has a type that is unknown.

**Flags**: reserved for boolean flags specific to the frame type. Flags are assigned semantics specific to the indicated frame type. Flags that have no defined semantics for a particular frame type MUST be ignored and MUST be left unset (0x0) when sending.

**R**: A reserved 1-bit field. The semantics of this bit are undefined, and the bit MUST remain unset (0x0) when sending and MUST be ignored when receiving.

**Stream Identifier**: The value 0x0 is reserved for frames that are associated with the connection as a whole as opposed to an individual stream.

**Frame payload**: The structure and content of the frame payload is dependent entirely on the frame type

## Frame Definitions

### Data

**Type**: `0x0`


DATA Frame Payload

```
 +---------------+
 |Pad Length? (8)|
 +---------------+-----------------------------------------------+
 |                            Data (*)                         ...
 +---------------------------------------------------------------+
 |                           Padding (*)                       ...
 +---------------------------------------------------------------+

```

_Pad Length_: An 8-bit field containing the length of the frame padding in units of octets. This field is conditional (as signified by a "?" in the diagram) and is only present if the PADDED flag is set.

_Data_: Application data. The amount of data is the remainder of the frame payload after subtracting the length of the other fields that are present.

_Padding_: Padding octets that contain no application semantic value. Padding octets MUST be set to zero when sending. A receiver is not obligated to verify padding but MAY treat non-zero padding as a connection error 


**Flag**: `0x1` or `0x8`

_END_STREAM (0x1)_: When set, bit 0 indicates that this frame is the last that the endpoint will send for the identified stream. Setting this flag causes the stream to enter one of the "half-closed" states or the "closed" state

_PADDED (0x8)_: When set, bit 3 indicates that the Pad Length field and any padding that it describes are present.


### Headers

**Type**: `0x1`

```
 +---------------+
 |Pad Length? (8)|
 +-+-------------+-----------------------------------------------+
 |E|                 Stream Dependency? (31)                     |
 +-+-------------+-----------------------------------------------+
 |  Weight? (8)  |
 +-+-------------+-----------------------------------------------+
 |                   Header Block Fragment (*)                 ...
 +---------------------------------------------------------------+
 |                           Padding (*)                       ...
 +---------------------------------------------------------------+

```



## Documents

[HTTP/2 - Wikipedia](https://en.wikipedia.org/wiki/HTTP/2)

[HTTP2 - github.io](https://http2.github.io/)

[HTTP2 - FAQ](https://http2.github.io/faq/)

[RFC7540 - IETF](https://tools.ietf.org/html/rfc7540)


## Notes

HTTP/2 leaves most of HTTP 1.1's high-level syntax, such as methods, status codes, header fields, and URIs, the same. The element that is modified is how the data is framed and transported between the client and the server

HTTP/2 allows the server to "push" content, that is, to respond with data for more queries than the client requested. This allows the server to supply data it knows a web browser will need to render a web page, without waiting for the browser to examine the first response, and without the overhead of an additional request cycle

The biggest difference between HTTP/1.1 and SPDY was that each user action in SPDY is given a "stream ID", meaning there is a single TCP channel connecting the user to the server. SPDY split requests into either control or data, using a "simple to parse binary protocol with two types of frames."[17] SPDY showed evident improvement from HTTP, with a new page load speedup ranging from 11.81% to 47.7%

Although the standard itself does not require usage of encryption,[26] most client implementations (Firefox,[27] Chrome, Safari, Opera, IE, Edge) have stated that they will only support HTTP/2 over TLS, which makes encryption de facto mandatory.[28]


## Question?

- Integrate into tcpip plugin or a separate plugin?
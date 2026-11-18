---
layout: default
title: "HTTP protocol"
---

# HTTP protocol

## HTTP message format

The HTTP generic message format is as follows:

```
<start-line>
<message-headers>
<empty-line>
[<message-body>]
[<message-trailers>]
```

### HTTP Request message format

```
<request-line>: <METHOD> <request-uri> <HTTP-VERSION>
<general-headers>: 
<request-headers>
<entity-headers>
<empty-line>
[<message-body>]
[<message-trailers>]
```

![http request message format](https://www.tcpipguide.com/free/diagrams/httprequest.png)

To know more about `METHOD`, [link](https://www.tcpipguide.com/free/t_HTTPMethods-2.htm)

### HTTP Response message format

```
<status-line>: <HTTP-VERSION> <status-code> <reason-phrase>
<general-headers>
<response-headers>
<entity-headers>
<empty-line>
[<message-body>]
[<message-trailers>]
```

![http response message format](https://www.tcpipguide.com/free/diagrams/httpresponse.png)


To know more about `status-code : reason-phrase`, [link](https://www.tcpipguide.com/free/t_HTTPStatusCodeFormatStatusCodesandReasonPhrases-2.htm)

### Multiple HTTP request over one TCP session

- [HTTP Data Length Issues, "Chunked" Transfers and Message Trailers ](https://www.tcpipguide.com/free/t_HTTPDataLengthIssuesChunkedTransfersandMessageTrai.htm)

**Chunked transfer**

```
<chunk-1-length>
<chunk-1-data>
<chunk-2-length>
<chunk-2-data>
...
0
<message-trailers>
```

Example HTTP Response Using Content-Length Header

```
HTTP/1.1 200 OK
Date: Mon, 22 Mar 2004 11:15:03 GMT
Content-Type: text/html
Content-Length: 129
Expires: Sat, 27 Mar 2004 21:12:00 GMT

<html><body><p>The file you requested is 3,400 bytes long and was last modified: Sat, 20 Mar 2004 21:12:00 GMT.</p></body></html>
```

Example HTTP Response Using Chunked Transfer Encoding

```
HTTP/1.1 200 OK
Date: Mon, 22 Mar 2004 11:15:03 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Trailer: Expires

29
<html><body><p>The file you requested is 
5
3,400
23
bytes long and was last modified: 
1d
Sat, 20 Mar 2004 21:12:00 GMT
13
.</p></body></html>
0
Expires: Sat, 27 Mar 2004 21:12:00 GMT
```

## Upgrade hand-off (issue #116)

A connection that starts as HTTP can switch protocols: the client sends a request with `Upgrade:` and `Connection: Upgrade` headers, and the server accepts with `101 Switching Protocols` (WebSocket, OCPP). mmt-dpi has no dissector for the upgraded protocol, so the session stays `http` unless a plugin takes it over.

HTTP offers the session where llhttp reports the upgrade (`src/mmt_tcpip/lib/protocols/proto_http.c:369`, through `mmt_http_offer_upgrade()` at `src/mmt_tcpip/lib/http_parser_integration.h:134`):

- only on the response parser that paused on a `101` answer, and once per direction;
- to the classifiers registered with `register_upgrade_classification_function(PROTO_HTTP, …)`, in weight order. Each is called with the packet and HTTP's index; one claims the session by calling `mmt_session_handover(ipacket, index, its_proto_id)`, and the offer stops at the first claim.

The `101` packet itself is still HTTP (statistics, attributes and `HTTP_HEADER` events); the next packet of the session belongs to the plugin, which gets the layer with an empty session-data slot, its own `session_data_init` and its analysis from then on ([MMT Sessions](./MMT-Session.md#handing-a-layer-to-another-protocol)). The plugin can give the session back with `mmt_session_handover(ipacket, index, PROTO_HTTP)`: HTTP then allocates a fresh parser on the next payload and parses the requests that follow; HTTP sub-services that come from the TCP flow (`http.facebook`) are not re-added on a given-back layer.

A refused upgrade — any other status, or a `101` no classifier claims — stays HTTP with the same output as without a plugin. llhttp is not resumed after an upgrade, as before: the request parser that saw the Upgrade request stays paused, so the requests that follow on a refused connection report no `HTTP_HEADER` events. The reasons are recorded in [DECISIONS.md](./DECISIONS.md).


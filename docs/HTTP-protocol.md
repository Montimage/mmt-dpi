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

![http request message format](http://www.tcpipguide.com/free/diagrams/httprequest.png)

To know more about `METHOD`, [link](http://www.tcpipguide.com/free/t_HTTPMethods-2.htm)

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

![http response message format](http://www.tcpipguide.com/free/diagrams/httpresponse.png)


To know more about `status-code : reason-phrase`, [link](http://www.tcpipguide.com/free/t_HTTPStatusCodeFormatStatusCodesandReasonPhrases-2.htm)

### Multiple HTTP request over one TCP session

- [HTTP Data Length Issues, "Chunked" Transfers and Message Trailers ](http://www.tcpipguide.com/free/t_HTTPDataLengthIssuesChunkedTransfersandMessageTrai.htm)

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
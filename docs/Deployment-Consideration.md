# Deployment Considerations

[TOC]

------------------


## Concurrent flows that system supports.

This metric depends on the HW specification and the available RAM:

    Number of concurrent flows ~= Total memory / 4K

This means: 

* 250K flows per 1GB memory.
* More than 5M flows for 32GB RAM

NOTE: MMT does not implement software restrictions on the number of concurrent flows.

## Number of new flows per second the system supports.

This metric depends on the HW specification and the available RAM, and, on a configuration parameter relative to the flows timeout value:

    Number of new flows per second ~> Number of concurrent flows/60

This means:

    > 4K flows per 1GB memory

NOTE: MMT does not implement software restrictions on the new flows rate. In case the system runs out of memory, MMT will force the timeout of least recently used flows to accommodate for the arrival of new flows. 

## Maximum supported number of subscriber for proposed system.

This metric depends on the HW specification and the available RAM. 

MMT does not implement software restrictions on the number of supported active users. For a smooth operation of the system, the maximum number of users should be 1/25 the number of active flows. That is, minimum of 10K users per 1GB memory

## Data buffering for packet classification

In order to extract data from not yet classified flows, data packets need to be buffered waiting the classification process. This procedure may consume system memory as follows:

```
D = f * d * v / n

With: 
•	D : total memory cost (in bytes)
•	f : average number of concurrent flows 
•	d : average packet size (in Bytes)
•	v : average classification speed (in number of packets)
•	n : average flow size (in number of packets)
```

Example : For a link with 10 million concurrent flows, and classification speed of 4 packets/flow, and average packet size of 500 Bytes and 50 packets per flow in average, the memory overhead would be: 

    10000000 * 500 * 4 /50 = 400 MB

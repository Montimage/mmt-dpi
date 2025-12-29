# Architecture Overview

MMT-DPI is a modular deep packet inspection framework built in C for high-performance network traffic analysis.

## System Architecture

```mermaid
graph TB
    subgraph "Application Layer"
        APP[User Application]
        SEC[Security Monitor]
        STATS[Traffic Statistics]
    end

    subgraph "MMT-DPI Framework"
        subgraph "Core Engine"
            HANDLER[mmt_handler_t<br/>Packet Handler]
            PROC[Packet Processor]
            SESS[Session Manager]
            REG[Protocol Registry]
        end

        subgraph "Infrastructure"
            MEMPOOL[Memory Pool<br/>O(1) allocation]
            HASH[Hash Table<br/>4096 slots]
            ERR[Error Framework]
            LOG[Logging System]
        end

        subgraph "Protocol Libraries"
            TCPIP[libmmt_tcpip<br/>50+ protocols]
            MOBILE[libmmt_mobile<br/>GTP/S1AP/NGAP]
            PLUGINS[Custom Plugins]
        end
    end

    subgraph "System Layer"
        PCAP[libpcap]
        PTHREAD[pthread]
        XML[libxml2]
    end

    APP --> HANDLER
    SEC --> HANDLER
    STATS --> HANDLER
    HANDLER --> PROC
    PROC --> SESS
    PROC --> REG
    REG --> TCPIP
    REG --> MOBILE
    REG --> PLUGINS
    SESS --> MEMPOOL
    SESS --> HASH
    PROC --> ERR
    PROC --> LOG
    HANDLER --> PCAP
    SESS --> PTHREAD

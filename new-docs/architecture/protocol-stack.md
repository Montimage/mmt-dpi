# Protocol Stack Architecture

MMT-DPI supports 200+ protocols organized in a layered hierarchy.

## Protocol Layers

```mermaid
graph TB
    subgraph "Layer 7 - Application"
        HTTP[HTTP/1.1]
        HTTP2[HTTP/2]
        DNS[DNS]
        FTP[FTP]
        SSH[SSH]
        TLS[SSL/TLS]
        QUIC[QUIC]
        NFS[NFS]
        SMTP[SMTP]
        MORE7[100+ more...]
    end

    subgraph "Layer 4 - Transport"
        TCP[TCP]
        UDP[UDP]
        SCTP[SCTP]
    end

    subgraph "Layer 3 - Network"
        IP[IPv4]
        IP6[IPv6]
        ICMP[ICMP]
        ICMP6[ICMPv6]
        ARP[ARP]
        GRE[GRE]
    end

    subgraph "Layer 2 - Data Link"
        ETH[Ethernet]
        VLAN[VLAN]
        PPP[PPP]
        LLC[LLC]
        BATMAN[BATMAN]
    end

    subgraph "Mobile Protocols"
        GTP[GTP-U/C]
        S1AP[S1AP<br/>LTE]
        NGAP[NGAP<br/>5G]
        NAS[NAS]
        DIAM[Diameter]
    end

    HTTP --> TCP
    HTTP2 --> TCP
    DNS --> UDP
    DNS --> TCP
    FTP --> TCP
    SSH --> TCP
    TLS --> TCP
    QUIC --> UDP
    MORE7 --> TCP
    MORE7 --> UDP

    TCP --> IP
    TCP --> IP6
    UDP --> IP
    UDP --> IP6
    SCTP --> IP

    IP --> ETH
    IP --> VLAN
    IP6 --> ETH
    GRE --> IP

    GTP --> UDP
    S1AP --> SCTP
    NGAP --> SCTP
    DIAM --> TCP
    DIAM --> SCTP
```

## Protocol Classification Flow

```mermaid
flowchart TD
    PKT[Incoming Packet] --> L2{Layer 2<br/>Detection}
    L2 -->|Ethernet| ETH[Parse Ethernet]
    L2 -->|PPP| PPP[Parse PPP]

    ETH --> ETYPE{EtherType?}
    ETYPE -->|0x0800| IPV4[Parse IPv4]
    ETYPE -->|0x86DD| IPV6[Parse IPv6]
    ETYPE -->|0x0806| ARP[Parse ARP]
    ETYPE -->|0x8100| VLAN[Parse VLAN]

    IPV4 --> PROTO{Protocol?}
    PROTO -->|6| TCP[Parse TCP]
    PROTO -->|17| UDP[Parse UDP]
    PROTO -->|1| ICMP[Parse ICMP]
    PROTO -->|47| GRE[Parse GRE]

    TCP --> PORT{Port-based<br/>Detection}
    UDP --> PORT

    PORT -->|80/8080| HTTP[HTTP Parser]
    PORT -->|443| TLS[TLS Parser]
    PORT -->|53| DNS[DNS Parser]
    PORT -->|21| FTP[FTP Parser]
    PORT -->|22| SSH[SSH Parser]
    PORT -->|Other| DPI{Deep Packet<br/>Inspection}

    DPI --> SIG[Signature<br/>Matching]
    SIG --> RESULT[Protocol<br/>Identified]
```

## Protocol Handler Structure

Each protocol handler implements:

```c
typedef struct protocol_t {
    uint32_t protocol_id;           // Unique protocol identifier
    const char *name;               // Human-readable name

    // Classification function
    int (*classify)(ipacket_t *packet, unsigned offset,
                    unsigned header_len);

    // Attribute extraction function
    int (*extract)(const ipacket_t *packet, unsigned offset,
                   attribute_t *attribute);

    // Session initialization
    void* (*session_init)(void);

    // Session cleanup
    void (*session_cleanup)(void *session_data);

    // Protocol-specific attributes
    attribute_metadata_t *attributes;
    int attribute_count;
} protocol_t;
```

## Protocol Libraries

### libmmt_tcpip

Location: `src/mmt_tcpip/lib/protocols/`

| Category | Protocols |
|----------|-----------|
| **Core** | Ethernet, IP, IPv6, TCP, UDP, ICMP |
| **Web** | HTTP, HTTP/2, SSL/TLS, QUIC |
| **Email** | SMTP, POP3, IMAP |
| **File Transfer** | FTP, TFTP, NFS |
| **Name Services** | DNS, mDNS, LLMNR |
| **Remote Access** | SSH, Telnet, RDP |
| **Tunneling** | GRE, VXLAN, MPLS, GTP |
| **Routing** | OSPF, BGP, RIP |
| **Streaming** | RTSP, RTP, RTCP |

### libmmt_mobile

Location: `src/mmt_mobile/`

| Protocol | Standard | Purpose |
|----------|----------|---------|
| **GTP** | 3GPP | GPRS Tunneling Protocol |
| **S1AP** | 3GPP | LTE signaling (eNB to MME) |
| **NGAP** | 3GPP | 5G signaling (gNB to AMF) |
| **NAS** | 3GPP | Non-Access Stratum messaging |
| **Diameter** | IETF | AAA signaling |

## Adding New Protocols

See [Adding Protocols Guide](../guides/adding-protocols.md) for step-by-step instructions.

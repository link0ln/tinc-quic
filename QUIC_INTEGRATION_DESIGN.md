# QUIC Integration Design for Tinc VPN

## Overview

This document outlines the architectural design for integrating Microsoft's MsQuic library into the tinc VPN daemon, replacing the current TCP/UDP transport layer with QUIC protocol.

## Goals

1. **Replace TCP/UDP Transport** - Use QUIC for both metadata and VPN packet transmission
2. **Leverage QUIC TLS** - Remove internal SPTPS encryption in favor of QUIC's native TLS 1.3
3. **Simplify Architecture** - Remove TCP-specific code and redundant encryption layers
4. **Improve Performance** - Utilize QUIC's 0-RTT, multiplexing, and connection migration
5. **Maintain Compatibility** - Keep the same metadata protocol and node discovery mechanisms

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                   Tinc Application                    │
├──────────────────────────────────────────────────────┤
│  Metadata Protocol (ID, ACK, PING, etc.)            │
│  VPN Packet Routing & Processing                     │
├──────────────────────────────────────────────────────┤
│           QUIC Transport Layer (NEW)                 │
│  ┌────────────────┬──────────────────────────┐      │
│  │ Control Stream │  VPN Packet Streams/     │      │
│  │  (Stream 0)    │  Datagrams               │      │
│  └────────────────┴──────────────────────────┘      │
├──────────────────────────────────────────────────────┤
│              MsQuic Library                          │
│  ┌──────────────────────────────────────────┐       │
│  │  TLS 1.3 Encryption + QUIC Protocol      │       │
│  └──────────────────────────────────────────┘       │
├──────────────────────────────────────────────────────┤
│                  UDP Socket                          │
└──────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Stream vs Datagram Usage

**Metadata Protocol → QUIC Stream 0 (Bidirectional)**
- Reliable, ordered delivery required
- Use dedicated bidirectional stream for control messages
- Maps directly to current TCP metadata connection

**VPN Packets → QUIC Datagrams**
- Fast, unreliable delivery preferred (like current UDP)
- Avoid head-of-line blocking
- Supports MTU discovery and variable packet sizes
- Falls back to streams if datagrams unavailable

### 2. Encryption Strategy

**Remove SPTPS Layer**
- QUIC provides TLS 1.3 encryption natively
- Ed25519 keys can be used as TLS certificates
- No need for separate ChaCha20-Poly1305 encryption
- Simplifies codebase significantly

**Certificate Handling**
- Generate self-signed certificates from Ed25519 keys
- Use existing tinc key infrastructure
- Maintain current trust model (manual key exchange)

### 3. Connection Management

**Current Structure:**
```c
typedef struct connection_t {
    char *name;
    union sockaddr_t address;
    int socket;              // TCP socket
    sptps_t sptps;          // SPTPS context
    cipher_t *incipher;     // Legacy encryption
    // ...
}
```

**New Structure:**
```c
typedef struct connection_t {
    char *name;
    union sockaddr_t address;

    // QUIC-specific fields
    HQUIC connection;        // MsQuic connection handle
    HQUIC control_stream;    // Metadata stream
    HQUIC api;              // MsQuic API table

    // Buffers
    struct buffer_t inbuf, outbuf;

    // Remove: socket, sptps, ciphers
}
```

### 4. Event Loop Integration

**MsQuic Async Model:**
- MsQuic uses callback-based event handling
- Integrates with tinc's existing event loop
- No separate MsQuic event loop needed

**Integration Approach:**
```c
// Register QUIC callbacks with tinc event system
void quic_connection_callback(HQUIC conn, void *ctx, QUIC_CONNECTION_EVENT *event) {
    switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            // Trigger tinc connection established
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            // Handle new stream
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            // Process VPN packet
            break;
    }
}
```

## Implementation Plan

### Phase 1: Build System & Dependencies

**Files to Modify:**
- `configure.ac` - Add MsQuic detection
- `Makefile.am` - Link against libmsquic
- `README.md` - Update dependencies

**Tasks:**
1. Add MsQuic as git submodule or external dependency
2. Configure autotools to detect/build MsQuic
3. Add compilation flags for QUIC support

### Phase 2: QUIC Abstraction Layer

**New Files:**
- `src/quic.h` - QUIC abstraction header
- `src/quic.c` - QUIC connection management
- `src/quic_packet.c` - Packet transmission via QUIC

**Core Functions:**
```c
// Initialize QUIC library
bool quic_init(void);
void quic_cleanup(void);

// Connection management
bool quic_connection_open(connection_t *c);
bool quic_connection_start(connection_t *c);
void quic_connection_close(connection_t *c);

// Data transmission
bool quic_send_meta(connection_t *c, const char *buffer, size_t len);
bool quic_send_packet(connection_t *c, vpn_packet_t *packet);

// Callbacks
void quic_connection_callback(HQUIC conn, void *ctx, QUIC_CONNECTION_EVENT *event);
void quic_stream_callback(HQUIC stream, void *ctx, QUIC_STREAM_EVENT *event);
```

### Phase 3: Modify Connection Layer

**Files to Modify:**
- `src/connection.h` - Add QUIC fields
- `src/connection.c` - Update lifecycle functions
- `src/net_setup.c` - Initialize QUIC instead of TCP/UDP
- `src/net_socket.c` - Replace socket creation with QUIC listener

**Key Changes:**
1. Replace `listen_socket_t` with QUIC listener
2. Remove TCP socket handling
3. Add QUIC configuration setup

### Phase 4: Migrate Metadata Protocol

**Files to Modify:**
- `src/meta.c` - Replace send_meta/receive_meta with QUIC versions
- `src/protocol.c` - Ensure protocol handlers work with QUIC transport
- `src/protocol_auth.c` - Remove SPTPS handshake (use TLS)

**Changes:**
1. `send_meta()` → Send on QUIC control stream
2. `receive_meta()` → Receive from QUIC stream callback
3. Remove SPTPS encryption/decryption
4. Keep protocol text format unchanged

### Phase 5: Migrate VPN Packet Transmission

**Files to Modify:**
- `src/net_packet.c` - Use QUIC datagrams for packets
- `src/net.c` - Update event loop for QUIC events

**Changes:**
1. `send_udppacket()` → `quic_send_datagram()`
2. `handle_incoming_vpn_data()` → QUIC datagram callback
3. Remove UDP socket handling
4. Keep MTU discovery logic

### Phase 6: Remove Legacy Code

**Files to Remove/Modify:**
- `src/sptps.c`, `src/sptps.h` - Remove SPTPS entirely
- `src/chacha-poly1305/*` - Remove (QUIC uses TLS)
- `src/openssl/cipher.c` - Remove cipher wrappers
- TCP-only code paths in `net_socket.c`

**Configuration Options to Remove:**
- `TCPOnly` - QUIC handles everything
- `UDPDiscovery` - QUIC manages connection migration
- Cipher/Digest settings - TLS 1.3 handles this

### Phase 7: Testing & Validation

**Test Cases:**
1. Single connection establishment
2. Multi-node mesh network
3. Connection migration (IP change)
4. Large file transfer
5. Latency/throughput benchmarks
6. Edge cases (packet loss, reordering)

## API Mapping

| Tinc Current | QUIC Replacement |
|-------------|------------------|
| TCP socket creation | `MsQuicListenerOpen()` |
| `connect()` | `MsQuicConnectionStart()` |
| `send()` metadata | `MsQuicStreamSend()` stream 0 |
| `recv()` metadata | `QUIC_STREAM_EVENT_RECEIVE` |
| `sendto()` UDP packet | `MsQuicDatagramSend()` |
| `recvfrom()` UDP packet | `QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED` |
| SPTPS handshake | TLS 1.3 handshake (automatic) |
| ChaCha20-Poly1305 | TLS_AES_128_GCM_SHA256 |

## Configuration Changes

**New Options:**
```
QuicALPN = tinc-vpn                    # ALPN protocol identifier
QuicCertFile = /etc/tinc/net/cert.pem  # TLS certificate
QuicKeyFile = /etc/tinc/net/key.pem    # TLS private key
QuicUseDatagrams = yes                 # Use datagrams for VPN packets
QuicMaxStreams = 100                   # Max concurrent streams
```

**Removed Options:**
- `TCPOnly` - No longer relevant
- `Cipher`, `Digest` - TLS handles encryption
- `ExperimentalProtocol` - QUIC is the only protocol

## Security Considerations

### 1. Certificate Validation

**Current (SPTPS):**
- Manual Ed25519 public key exchange
- Keys stored in `/etc/tinc/net/hosts/`

**With QUIC:**
- Generate X.509 cert from Ed25519 key
- Custom TLS certificate verification callback
- Maintain manual trust model

### 2. Forward Secrecy

- TLS 1.3 provides forward secrecy by default
- Ephemeral key exchange (ECDHE)
- No long-term key compromise risk

### 3. Downgrade Protection

- Remove legacy protocol support entirely
- All nodes must use QUIC
- Version incompatibility detected early

## Performance Expectations

### Benefits

1. **0-RTT Connection** - Faster reconnection
2. **Multiplexing** - No head-of-line blocking
3. **Better Loss Recovery** - Improved congestion control
4. **Connection Migration** - Seamless IP changes

### Trade-offs

1. **CPU Usage** - TLS encryption overhead
2. **Memory** - QUIC state management
3. **MTU** - QUIC header overhead (~50 bytes)

## Migration Path

### For Existing Deployments

**Option 1: Hard cutover**
- Upgrade all nodes simultaneously
- No backward compatibility

**Option 2: Dual-stack (future work)**
- Support both TCP/UDP and QUIC temporarily
- Gradual migration
- Requires maintaining both code paths

**Recommendation:** Start with Option 1 for simplicity

## Open Questions

1. **Datagram vs Stream for VPN packets?**
   - Decision: Use datagrams (unreliable, fast)
   - Rationale: Matches current UDP behavior

2. **Certificate generation?**
   - Decision: Auto-generate from Ed25519 keys
   - Store in same directory as host files

3. **ALPN identifier?**
   - Decision: "tinc-vpn-quic"
   - Ensures tinc nodes only connect to tinc nodes

4. **Backward compatibility?**
   - Decision: None (breaking change)
   - Document as tinc 2.0

## Timeline Estimate

| Phase | Effort | Duration |
|-------|--------|----------|
| 1. Build system | Low | 1 day |
| 2. QUIC abstraction | Medium | 3 days |
| 3. Connection layer | Medium | 2 days |
| 4. Metadata migration | High | 4 days |
| 5. Packet migration | High | 4 days |
| 6. Legacy removal | Medium | 2 days |
| 7. Testing | High | 5 days |
| **Total** | | **~3 weeks** |

## References

- [MsQuic GitHub](https://github.com/microsoft/msquic)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [Tinc Documentation](https://www.tinc-vpn.org/documentation/)

## Conclusion

Integrating QUIC into tinc will modernize the transport layer, improve performance, and simplify the codebase by removing redundant encryption. The well-structured tinc architecture makes this integration feasible with focused changes to the transport layer while preserving the metadata protocol and routing logic.

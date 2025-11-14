# Tinc-QUIC Docker Testing Environment

This directory contains Docker configuration and scripts for building and testing tinc with MsQuic support.

## Overview

The Docker environment provides:
- Multi-stage build with MsQuic library
- 3-node test network (node1 as router, node2 and node3 as clients)
- Automated testing with organized logging
- Network isolation for realistic testing scenarios

## Quick Start

```bash
cd docker

# Build and test
make test

# Or build and run manually
make build
make up

# View logs
make logs

# Test connectivity
make test-ping

# Access node shell
make shell-node1
```

## Architecture

### Network Topology

```
node2 (172.25.1.11) ────┐
                         ├──── node1 (172.25.1.10 / 172.25.2.10)
node3 (172.25.2.12) ────┘
```

- **network_12**: Connects node1 and node2 (172.25.1.0/24)
- **network_13**: Connects node1 and node3 (172.25.2.0/24)
- node2 and node3 can only communicate through node1's tinc VPN

### VPN Addresses

- node1: 10.0.0.1
- node2: 10.0.0.2
- node3: 10.0.0.3

## Files

### Build Configuration

- **Dockerfile** - Multi-stage build with MsQuic (stage 1) and tinc (stage 2)
- **docker-compose.yml** - Container orchestration for 3-node network
- **Makefile** - Build and test automation

### Scripts

- **redeploy-test-logs.sh** - Complete rebuild, deploy, and test with organized logging
- **scripts/entrypoint.sh** - Container startup script with QUIC initialization
- **scripts/generate-keys.sh** - Generate tinc keys for nodes
- **scripts/setup-configs.sh** - Setup tinc configurations

### Node Configurations

Each node has its own directory:
- **node1/tinc/** - Node1 tinc configuration and keys
- **node2/tinc/** - Node2 tinc configuration and keys
- **node3/tinc/** - Node3 tinc configuration and keys

## Logging

The test script (`redeploy-test-logs.sh`) organizes logs into separate files in `docker/logs/`:

### Log Files

| File | Description |
|------|-------------|
| `build.log` | Docker image build output |
| `deployment.log` | Container deployment and status |
| `network-info.log` | Network configuration from all nodes |
| `connectivity-tests.log` | Ping test results between all nodes |
| `tinc-state.log` | Tinc daemon state dumps (nodes, connections, edges) |
| `node1-quic.log` | Node1 QUIC-specific logs (handshake, connections) |
| `node2-quic.log` | Node2 QUIC-specific logs |
| `node3-quic.log` | Node3 QUIC-specific logs |
| `node1-full.log` | Complete Node1 container logs |
| `node2-full.log` | Complete Node2 container logs |
| `node3-full.log` | Complete Node3 container logs |
| `errors.log` | All errors and warnings from all nodes |
| `summary.log` | Test summary with pass/fail status |

### Viewing Logs

```bash
# View specific log
cat logs/summary.log
cat logs/connectivity-tests.log
cat logs/node1-quic.log

# Monitor errors
tail -f logs/errors.log

# Search for QUIC handshake issues
grep -i "handshake" logs/node*-quic.log
```

## Makefile Targets

### Build Commands

```bash
make build           # Build Docker images
make build-no-cache  # Clean build without cache
```

### Container Management

```bash
make up              # Start all containers
make down            # Stop and remove containers
make restart         # Restart all containers
```

### Testing

```bash
make test            # Run full test suite with organized logs
make test-ping       # Quick connectivity test
make logs            # View live container logs
```

### Cleanup

```bash
make clean           # Stop containers and remove networks
make clean-images    # Remove old/dangling images
make clean-logs      # Remove all log files
make clean-all       # Full cleanup (containers, images, volumes, logs)
make prune           # Docker system prune
```

### Shell Access

```bash
make shell-node1     # Open bash shell in node1
make shell-node2     # Open bash shell in node2
make shell-node3     # Open bash shell in node3
```

### Information

```bash
make images-size     # Show Docker image sizes
make disk-usage      # Show Docker disk usage
```

## MsQuic Integration

### Build Process

1. **Stage 1**: Build MsQuic library
   - Clone/copy MsQuic submodule
   - Build with OpenSSL TLS backend
   - Generate libmsquic.so

2. **Stage 2**: Build tinc
   - Copy MsQuic library from stage 1
   - Run autoconf with `--with-msquic`
   - Link tinc with MsQuic

### Configuration

MsQuic is enabled via:
- `configure.ac`: MsQuic detection and flags
- `src/Makefile.am`: Link MsQuic library to tincd
- `src/quic.c`: MsQuic implementation

### Runtime

- MsQuic library loaded at runtime
- TLS certificates auto-generated if missing
- QUIC port: 4433 (mapped to host)

## Debugging

### Enable verbose logging

Containers run with `-d5` (maximum debug level) by default.

### Check QUIC initialization

```bash
# View QUIC-specific logs
make shell-node1
grep QUIC /var/log/tinc/*

# Or check organized logs
cat logs/node1-quic.log
```

### Check MsQuic library

```bash
make shell-node1
ldconfig -p | grep msquic
ldd /usr/sbin/tincd | grep msquic
```

### Network troubleshooting

```bash
# Check tinc0 interface
make shell-node1
ip a show dev tinc0
ip r

# Check tinc connections
tinc -n testvpn dump nodes
tinc -n testvpn dump connections
tinc -n testvpn dump edges

# Check Docker networks
docker network ls
docker network inspect docker_network_12
```

### Container logs

```bash
# Live logs
docker logs -f tinc-node1

# Or use organized logs
cat logs/node1-full.log
```

## Common Issues

### Build failures

```bash
# Clean rebuild
make clean-all
make build-no-cache
```

### Connectivity issues

1. Check container status: `docker ps`
2. Check network interfaces: `make shell-node1` → `ip a`
3. Check tinc state: `tinc -n testvpn dump nodes`
4. Check logs: `cat logs/errors.log`

### MsQuic not found

```bash
# Verify MsQuic in image
make shell-node1
find /usr -name "libmsquic.so*"
ldconfig -p | grep msquic
```

## Testing Checklist

After making changes:

1. Clean build: `make clean-all && make build-no-cache`
2. Run tests: `make test`
3. Check summary: `cat logs/summary.log`
4. Review errors: `cat logs/errors.log`
5. Verify QUIC: `grep -i "quic" logs/node*-quic.log`
6. Test connectivity: All 6 ping tests should pass

## Development Workflow

```bash
# 1. Make code changes to tinc source
vim ../src/quic.c

# 2. Rebuild and test
make test

# 3. Check results
cat logs/summary.log

# 4. Debug if needed
cat logs/errors.log
cat logs/node1-quic.log

# 5. Iterate
```

## Production Deployment

This Docker environment is for **testing only**. For production:

1. Build tinc with MsQuic on target system
2. Generate proper TLS certificates (not self-signed)
3. Configure firewall for QUIC port (UDP 4433)
4. Use appropriate debug level (not -d5)
5. Set up proper logging and monitoring

## References

- [MsQuic Documentation](https://github.com/microsoft/msquic)
- [Tinc VPN Documentation](https://www.tinc-vpn.org/documentation/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)

#!/usr/bin/env python3
"""
QUIC SNI Checker - Verify SNI usage in QUIC connections
Tests tinc QUIC nodes to ensure custom SNI domains are used
"""

import asyncio
import argparse
import sys
from typing import Optional

try:
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3_ALPN
except ImportError:
    print("ERROR: aioquic library not installed")
    print("Install with: pip3 install aioquic")
    sys.exit(1)


class QuicSniTester:
    """Test QUIC connections with custom SNI"""

    def __init__(self, host: str, port: int, sni: str):
        self.host = host
        self.port = port
        self.sni = sni
        self.success = False

    async def test_connection(self, timeout: int = 5) -> bool:
        """Attempt QUIC connection with specified SNI"""

        # Configure QUIC
        configuration = QuicConfiguration(
            alpn_protocols=["quic"],  # tinc uses "quic" ALPN
            is_client=True,
            server_name=self.sni,  # This is the SNI we're testing!
        )

        # Disable certificate validation (tinc uses self-signed certs)
        configuration.verify_mode = False

        print(f"🔍 Testing QUIC connection:")
        print(f"   Host: {self.host}:{self.port}")
        print(f"   SNI:  {self.sni}")
        print(f"   ALPN: quic")
        print()

        try:
            async with connect(
                self.host,
                self.port,
                configuration=configuration,
            ) as protocol:
                print(f"✅ Connection successful!")
                print(f"   SNI used: {self.sni}")

                # Try to get connection details if available
                try:
                    if hasattr(protocol, '_quic'):
                        if hasattr(protocol._quic, '_network_paths') and protocol._quic._network_paths:
                            print(f"   Remote: {protocol._quic._network_paths[0].addr}")

                        # Get connection stats if available
                        if hasattr(protocol._quic, '_loss'):
                            stats = protocol._quic._loss._statistics
                            print(f"\n📊 Connection stats:")
                            print(f"   Packets sent: {stats.packets_sent}")
                            print(f"   Packets received: {stats.packets_received}")
                except AttributeError:
                    pass  # Stats not available in this version

                self.success = True
                await asyncio.sleep(0.5)

        except Exception as e:
            print(f"❌ Connection failed: {e}")
            import traceback
            traceback.print_exc()
            self.success = False

        return self.success


async def test_node(host: str, port: int, sni: str) -> bool:
    """Test a single node with given SNI"""
    tester = QuicSniTester(host, port, sni)
    return await tester.test_connection()


async def test_all_nodes():
    """Test all tinc nodes with their configured SNI"""

    tests = [
        # Node1: Uses default pool (12 domains)
        ("10.2.2.10", 443, "www.cloudflare.com"),

        # Node2: Uses custom 3-domain pool
        ("10.2.2.11", 443, "cdn.jsdelivr.net"),

        # Node3: Uses custom 6-domain pool
        ("10.2.2.12", 443, "www.google.com"),
    ]

    print("=" * 70)
    print("QUIC SNI Verification Test Suite")
    print("=" * 70)
    print()

    results = []
    for host, port, sni in tests:
        success = await test_node(host, port, sni)
        results.append((host, sni, success))
        print()
        print("-" * 70)
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    all_success = True
    for host, sni, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}  {host:15s}  SNI: {sni}")
        if not success:
            all_success = False

    print()
    if all_success:
        print("🎉 All tests passed! SNI configuration verified.")
        return 0
    else:
        print("⚠️  Some tests failed. Check configuration.")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Test QUIC SNI configuration for tinc nodes"
    )
    parser.add_argument(
        "--host",
        help="Target host IP",
        default=None
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Target port (default: 443)",
        default=443
    )
    parser.add_argument(
        "--sni",
        help="SNI to use for connection",
        default=None
    )
    parser.add_argument(
        "--test-all",
        action="store_true",
        help="Test all tinc nodes with their configured SNI"
    )

    args = parser.parse_args()

    if args.test_all:
        # Test all nodes
        exit_code = asyncio.run(test_all_nodes())
        sys.exit(exit_code)
    elif args.host and args.sni:
        # Test single node
        success = asyncio.run(test_node(args.host, args.port, args.sni))
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        print()
        print("Examples:")
        print("  # Test all nodes:")
        print("  python3 quic-sni-checker.py --test-all")
        print()
        print("  # Test single node:")
        print("  python3 quic-sni-checker.py --host 10.2.2.10 --sni www.cloudflare.com")
        sys.exit(1)


if __name__ == "__main__":
    main()

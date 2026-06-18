"""
Allow running oida as a module: python -m oida

This enables the following usage patterns:
    python -m oida modbus 192.168.1.100
    python -m oida opcua opc.tcp://host:4840 --browse
    python -m oida --help
"""

import sys

from oida.cli import main

if __name__ == "__main__":
    sys.exit(main())

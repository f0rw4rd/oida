#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP protocol argument parsing.

Tests cover:
- proto_args function existence and behavior
- Argument groups and options
- Default values
"""

import argparse
import unittest

import pytest

pytestmark = pytest.mark.core


class TestProtoArgs(unittest.TestCase):
    """Test EtherNet/IP protocol argument registration."""

    def test_proto_args_callable(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        self.assertTrue(callable(proto_args))

    def test_proto_args_creates_subparser(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        result = proto_args(subparsers, [parent])
        self.assertIsNotNone(result)

    def test_proto_args_default_port(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100"])
        self.assertEqual(args.port, 44818)

    def test_proto_args_custom_port(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100", "--port", "5000"])
        self.assertEqual(args.port, 5000)

    def test_proto_args_enumerate_all(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100", "--enumerate-all"])
        self.assertTrue(args.enumerate_all)

    def test_proto_args_list_commands(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100", "--list-services"])
        self.assertTrue(args.list_services)

    def test_proto_args_cip_options(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(
            [
                "192.168.1.100",
                "--maxclass",
                "100",
                "--exploreclass",
                "0x1,2,3",
                "--maxattributes",
                "50",
                "--route-path",
                "1/2,1/0",
                "--slot",
                "3",
            ]
        )
        self.assertEqual(args.maxclass, 100)
        self.assertEqual(args.exploreclass, "0x1,2,3")
        self.assertEqual(args.maxattributes, 50)
        self.assertEqual(args.route_path, "1/2,1/0")
        self.assertEqual(args.slot, 3)

    def test_proto_args_security_options(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        # Default: check_security=True
        args = enip_parser.parse_args(["192.168.1.100"])
        self.assertTrue(args.check_security)

        # Disable security check
        args = enip_parser.parse_args(["192.168.1.100", "--no-check-security"])
        self.assertFalse(args.check_security)

    def test_proto_args_dump_security_defaults_off(self):
        """--dump-security is the heavy opt-in path and must default to False.

        Regression: the flag was registered with
        default=True, so the cert download + Password Authenticator (0x61)
        read ran on every host even when the user never asked for it.
        """
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        # Default: dump_security must be OFF (no heavy dump on a plain scan).
        args = enip_parser.parse_args(["192.168.1.100"])
        self.assertFalse(args.dump_security)

        # Explicitly requesting it turns it on.
        args = enip_parser.parse_args(["192.168.1.100", "--dump-security"])
        self.assertTrue(args.dump_security)

        # --no-dump-security keeps it off (explicit, harmless default).
        args = enip_parser.parse_args(["192.168.1.100", "--no-dump-security"])
        self.assertFalse(args.dump_security)

    def test_proto_args_write_and_fuzz(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100", "--write", "--fuzz"])
        self.assertTrue(args.write)
        self.assertTrue(args.fuzz)

    def test_proto_args_attack_options(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(
            [
                "192.168.1.100",
                "--cpu-stop",
                "--crash-ethernet",
                "--reset-ethernet",
                "--confirm",
            ]
        )
        self.assertTrue(args.cpu_stop)
        self.assertTrue(args.crash_ethernet)
        self.assertTrue(args.reset_ethernet)
        self.assertTrue(args.confirm)

    def test_proto_args_file_options(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(
            [
                "192.168.1.100",
                "--download-files",
                "--file-output",
                "/tmp/files",
                "--max-file-size",
                "1024",
            ]
        )
        self.assertTrue(args.download_files)
        self.assertEqual(args.file_output, "/tmp/files")
        self.assertEqual(args.max_file_size, 1024)

    def test_proto_args_deep_and_full_scan(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(
            [
                "192.168.1.100",
                "--deep-scan",
                "--full-scan",
                "--show-udts",
                "--full-enum",
            ]
        )
        self.assertTrue(args.deep_scan)
        self.assertTrue(args.full_scan)
        self.assertTrue(args.show_udts)
        self.assertTrue(args.full_enum)

    def test_proto_args_tag_dump(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(
            [
                "192.168.1.100",
                "--dump-tags",
                "--tag-output",
                "/tmp/tags",
            ]
        )
        self.assertTrue(args.dump_tags)
        self.assertEqual(args.tag_output, "/tmp/tags")

    def test_proto_args_default_maxclass(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100"])
        self.assertEqual(args.maxclass, 0)

    def test_proto_args_default_maxattributes(self):
        from oida.protocols.ethernetip.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        enip_parser = proto_args(subparsers, [parent])

        args = enip_parser.parse_args(["192.168.1.100"])
        self.assertEqual(args.maxattributes, 100)


if __name__ == "__main__":
    unittest.main()

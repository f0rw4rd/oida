"""Feature-flag coverage for MQTT proto_args."""

import argparse

import pytest

from oida.protocols.mqtt.proto_args import proto_args


def _parse(*flags):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["mqtt", "127.0.0.1", *flags])


class TestMQTTProtoArgs:
    def test_target_positional(self):
        assert _parse().target == "127.0.0.1"

    def test_default_port(self):
        assert _parse().port == 1883

    def test_client_id(self):
        args = _parse("--client-id", "oida-test")
        assert args.client_id == "oida-test"

    def test_protocol_version_default(self):
        assert hasattr(_parse(), "protocol_version")

    def test_protocol_version_5(self):
        args = _parse("--protocol-version", "5")
        assert int(args.protocol_version) == 5

    def test_enumerate_flag(self):
        assert _parse("--enumerate").enumerate is True

    def test_topics(self):
        args = _parse("--topics", "sensor/#")
        assert args.topics == "sensor/#"

    def test_enumerate_common_flag(self):
        assert _parse("--enumerate-common").enumerate_common is True

    def test_topic_list(self):
        args = _parse("--topic-list", "/tmp/topics.txt")
        assert args.topic_list == "/tmp/topics.txt"

    def test_unique_flag(self):
        assert _parse("--unique").unique is True

    def test_message(self):
        args = _parse("--message", "hello world")
        assert args.message == "hello world"

    def test_payload_file(self):
        args = _parse("--payload-file", "/tmp/payload.bin")
        assert args.payload_file == "/tmp/payload.bin"

    def test_null_flag(self):
        assert _parse("--null").null is True

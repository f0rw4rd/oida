"""Feature-flag coverage for DICOM proto_args."""

import argparse


from oida.protocols.dicom.proto_args import proto_args


def _parse(*flags):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["dicom", "127.0.0.1", *flags])


class TestDICOMProtoArgs:
    def test_target_positional(self):
        assert _parse().target == "127.0.0.1"

    def test_default_port(self):
        assert _parse().port == 104

    def test_aet(self):
        args = _parse("--aet", "OIDA_SCU")
        assert args.aet == "OIDA_SCU"

    def test_called_aet(self):
        args = _parse("--called-aet", "DCMQRSCP")
        assert args.called_aet == "DCMQRSCP"

    def test_max_pdu(self):
        args = _parse("--max-pdu", "32768")
        assert int(args.max_pdu) == 32768

    def test_find_flag(self):
        assert _parse("--find").find is True

    def test_get_flag(self):
        assert _parse("--get").get is True

    def test_store_flag(self):
        assert _parse("--store").store is True

    def test_move_flag(self):
        assert _parse("--move").move is True

    def test_probe_ops_flag(self):
        assert _parse("--probe-ops").probe_ops is True

    def test_dump_all_flag(self):
        assert _parse("--dump-all").dump_all is True

    def test_patient_id(self):
        args = _parse("--patient-id", "P12345")
        assert args.patient_id == "P12345"

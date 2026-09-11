"""
Unit tests for BACnet constants and lazy loading infrastructure.
"""

import unittest


class TestObjectTypes(unittest.TestCase):
    """Test BACnet object type constants."""

    def test_object_types_has_standard_types(self):
        from oida.protocols.bacnet.constants import OBJECT_TYPES

        self.assertEqual(OBJECT_TYPES[0], "analogInput")
        self.assertEqual(OBJECT_TYPES[8], "device")
        self.assertEqual(OBJECT_TYPES[56], "networkPort")

    def test_object_type_names_reverse_mapping(self):
        from oida.protocols.bacnet.constants import OBJECT_TYPES, OBJECT_TYPE_NAMES

        for type_id, name in OBJECT_TYPES.items():
            self.assertEqual(OBJECT_TYPE_NAMES[name], type_id)

    def test_control_point_types(self):
        from oida.protocols.bacnet.constants import CONTROL_POINT_TYPES

        self.assertIn("analogInput", CONTROL_POINT_TYPES)
        self.assertIn("binaryOutput", CONTROL_POINT_TYPES)
        self.assertNotIn("device", CONTROL_POINT_TYPES)
        self.assertNotIn("schedule", CONTROL_POINT_TYPES)

    def test_vendors_dict(self):
        from oida.protocols.bacnet.constants import VENDORS

        self.assertEqual(VENDORS[0], "ASHRAE")
        self.assertEqual(VENDORS[7], "Siemens Schweiz AG")
        self.assertIsInstance(VENDORS, dict)

    def test_priority_levels(self):
        from oida.protocols.bacnet.constants import BACNET_PRIORITY_LEVELS

        self.assertEqual(len(BACNET_PRIORITY_LEVELS), 16)
        self.assertIn("Life Safety", BACNET_PRIORITY_LEVELS[1])
        self.assertIn("Operator", BACNET_PRIORITY_LEVELS[8])


class TestBac0Availability(unittest.TestCase):
    """Test BAC0 availability check."""

    def test_is_bac0_available_returns_bool(self):
        from oida.protocols.bacnet.constants import _is_bac0_available

        result = _is_bac0_available()
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()

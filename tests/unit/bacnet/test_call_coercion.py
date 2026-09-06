"""Unit tests for BACnet --call value coercion (_coerce_atomic).

Locks in the datatype mapping, especially the active/inactive -> Enumerated
(BinaryPV) vs true/false -> Boolean disambiguation: a binary object's
present-value is BinaryPV (Enumerated), NOT Boolean, so coercing "active" to
Boolean makes a spec-compliant device reject the WriteProperty as
invalid-data-type. Override with an explicit type prefix (bool:/enum:/...).
"""

import unittest

try:
    import bacpypes3  # noqa: F401

    _HAS = True
except ImportError:
    _HAS = False


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestCoerceAtomic(unittest.TestCase):
    def setUp(self):
        from oida.protocols.bacnet.mixins.call import CallMixin

        # _coerce_atomic does not touch instance state; a bare instance is fine.
        self.coerce = CallMixin._coerce_atomic.__get__(object.__new__(CallMixin))

    def _type(self, value):
        return type(self.coerce(value)).__name__

    def test_binary_present_value_keywords_are_enumerated_not_boolean(self):
        # The regression: "active"/"inactive" must be BinaryPV (Enumerated),
        # because that is a binary present-value's datatype.
        self.assertEqual(self._type("active"), "Enumerated")
        self.assertEqual(self._type("inactive"), "Enumerated")
        self.assertEqual(int(self.coerce("active")), 1)
        self.assertEqual(int(self.coerce("inactive")), 0)

    def test_boolean_keywords_are_boolean(self):
        self.assertEqual(self._type("true"), "Boolean")
        self.assertEqual(self._type("false"), "Boolean")
        self.assertTrue(bool(self.coerce("true")))
        self.assertFalse(bool(self.coerce("false")))

    def test_numeric_inference(self):
        self.assertEqual(self._type("42.5"), "Real")
        self.assertEqual(self._type("5"), "Unsigned")
        self.assertEqual(self._type("-3"), "Integer")
        self.assertEqual(self._type("hello"), "CharacterString")

    def test_explicit_type_prefixes_override(self):
        self.assertEqual(self._type("bool:true"), "Boolean")
        self.assertEqual(self._type("enum:2"), "Enumerated")
        self.assertEqual(int(self.coerce("enum:2")), 2)
        self.assertEqual(self._type("uint:5"), "Unsigned")
        self.assertEqual(self._type("int:-3"), "Integer")
        self.assertEqual(self._type("real:1.0"), "Real")
        # str: forces a CharacterString even for a value that would otherwise
        # infer as a number/keyword.
        self.assertEqual(self._type("str:active"), "CharacterString")
        self.assertEqual(str(self.coerce("str:active")), "active")


if __name__ == "__main__":
    unittest.main()

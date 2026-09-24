"""
MQTT Protocol Mixins

This package contains mixin classes that provide specific functionality
for the MQTT scanner class. Each mixin handles a logical group
of related operations.

Mixins:
    - ConnectionMixin: Client creation, TLS, MQTT 5.0 properties, connection attempts
    - TopicDiscoveryMixin: $SYS, wildcard, Sparkplug B, and common topic enumeration
    - AuthMixin: Anonymous auth testing, credential testing, brute-force
    - MessagingMixin: Listen mode, publish, publish-and-listen, fuzzing
    - SecurityMixin: Security analysis and finding reporting
"""

from oida.protocols.mqtt.mixins.connection import ConnectionMixin
from oida.protocols.mqtt.mixins.topic_discovery import TopicDiscoveryMixin
from oida.protocols.mqtt.mixins.auth import AuthMixin
from oida.protocols.mqtt.mixins.messaging import MessagingMixin
from oida.protocols.mqtt.mixins.security import SecurityMixin

__all__ = [
    "ConnectionMixin",
    "TopicDiscoveryMixin",
    "AuthMixin",
    "MessagingMixin",
    "SecurityMixin",
]

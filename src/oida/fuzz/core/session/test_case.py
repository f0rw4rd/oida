"""
Test case metadata system for protocol fuzzers.

Provides a registry-based approach to fuzzer test cases with feature mapping,
enabling deterministic verification and selective execution.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum, auto

from ....utils.ics_logger import get_logger

_log = get_logger("REGISTRY", "test_case", 0)


class ProtocolFeature(Enum):
    """Base class for protocol feature enumerations"""


class HTTPFeature(ProtocolFeature):
    """HTTP protocol features that can be tested"""

    # Baseline connectivity
    HTTP_BASELINE = auto()

    # HTTP Methods
    HTTP_METHOD_GET = auto()
    HTTP_METHOD_POST = auto()
    HTTP_METHOD_PUT = auto()
    HTTP_METHOD_DELETE = auto()
    HTTP_METHOD_HEAD = auto()
    HTTP_METHOD_OPTIONS = auto()
    HTTP_METHOD_PATCH = auto()
    HTTP_METHOD_TRACE = auto()
    HTTP_METHOD_CONNECT = auto()

    # WebDAV Methods
    HTTP_METHOD_PROPFIND = auto()
    HTTP_METHOD_PROPPATCH = auto()
    HTTP_METHOD_MKCOL = auto()
    HTTP_METHOD_COPY = auto()
    HTTP_METHOD_MOVE = auto()
    HTTP_METHOD_LOCK = auto()
    HTTP_METHOD_UNLOCK = auto()

    # Common Headers
    HTTP_HEADER_HOST = auto()
    HTTP_HEADER_USER_AGENT = auto()
    HTTP_HEADER_ACCEPT = auto()
    HTTP_HEADER_ACCEPT_ENCODING = auto()
    HTTP_HEADER_CONTENT_TYPE = auto()
    HTTP_HEADER_CONTENT_LENGTH = auto()
    HTTP_HEADER_AUTHORIZATION = auto()
    HTTP_HEADER_COOKIE = auto()
    HTTP_HEADER_CONNECTION = auto()
    HTTP_HEADER_CACHE_CONTROL = auto()

    # Authentication
    HTTP_AUTH_BASIC = auto()
    HTTP_AUTH_BEARER = auto()
    HTTP_AUTH_DIGEST = auto()

    # Content Types
    HTTP_CONTENT_JSON = auto()
    HTTP_CONTENT_XML = auto()
    HTTP_CONTENT_FORM = auto()
    HTTP_CONTENT_MULTIPART = auto()

    # Request Components
    HTTP_URI_PATH = auto()
    HTTP_QUERY_STRING = auto()
    HTTP_FRAGMENT = auto()
    HTTP_BODY = auto()

    # Special Cases
    HTTP_MALFORMED_REQUEST = auto()
    HTTP_OVERFLOW_PATH = auto()
    HTTP_OVERFLOW_HEADER = auto()
    HTTP_INJECTION_HEADER = auto()
    HTTP_INJECTION_PARAM = auto()


class TCPFeature(ProtocolFeature):
    """TCP protocol features that can be tested"""

    # TCP Flags
    TCP_FLAG_SYN = auto()
    TCP_FLAG_ACK = auto()
    TCP_FLAG_PSH = auto()
    TCP_FLAG_FIN = auto()
    TCP_FLAG_RST = auto()
    TCP_FLAG_URG = auto()
    TCP_FLAG_ECE = auto()
    TCP_FLAG_CWR = auto()

    # TCP Options
    TCP_OPTION_MSS = auto()
    TCP_OPTION_WINDOW_SCALE = auto()
    TCP_OPTION_TIMESTAMPS = auto()
    TCP_OPTION_SACK_PERMITTED = auto()
    TCP_OPTION_SACK = auto()
    TCP_OPTION_FAST_OPEN = auto()


@dataclass
class TestCaseDefinition:
    """
    Metadata for a single fuzzer test case.

    Attributes:
        id: Unique test case identifier (corresponds to boofuzz mutation index)
        name: Human-readable test case name
        category: Test category (e.g., "http_methods", "authentication", "overflow")
        features: Protocol features this test case exercises
        mutations: Specific mutations applied (field_name, value) pairs
        request_name: Name of the Request object in boofuzz protocol definition
        description: Optional detailed description
        expected_outcome: Expected result (e.g., "200 OK", "connection established")
    """

    id: int
    name: str
    category: str
    features: List[ProtocolFeature]
    mutations: Dict[str, Any] = field(default_factory=dict)
    request_name: str = ""
    description: str = ""
    expected_outcome: str = ""

    def has_feature(self, feature: ProtocolFeature) -> bool:
        """Check if this test case exercises a specific feature"""
        return feature in self.features

    def has_any_feature(self, features: List[ProtocolFeature]) -> bool:
        """Check if this test case exercises any of the given features"""
        return any(f in self.features for f in features)

    def has_all_features(self, features: List[ProtocolFeature]) -> bool:
        """Check if this test case exercises all of the given features"""
        return all(f in self.features for f in features)


class TestCaseRegistry:
    """
    Registry for managing fuzzer test cases with feature mapping.

    Provides filtering, querying, and organization of test cases by
    features, categories, and other metadata.
    """

    def __init__(self, protocol: str):
        """
        Initialize registry for a protocol.

        Args:
            protocol: Protocol name (e.g., 'http', 'tcp', 'mms')
        """
        self.protocol = protocol
        self.test_cases: List[TestCaseDefinition] = []
        self._by_id: Dict[int, TestCaseDefinition] = {}
        self._by_category: Dict[str, List[TestCaseDefinition]] = {}
        self._by_feature: Dict[ProtocolFeature, List[TestCaseDefinition]] = {}

    def register(self, test_case: TestCaseDefinition) -> None:
        """
        Register a test case in the registry.

        Args:
            test_case: Test case definition to register
        """
        if test_case.id in self._by_id:
            raise ValueError(f"Test case ID {test_case.id} already registered")

        self.test_cases.append(test_case)
        self._by_id[test_case.id] = test_case

        # Index by category
        if test_case.category not in self._by_category:
            self._by_category[test_case.category] = []
        self._by_category[test_case.category].append(test_case)

        # Index by features
        for feature in test_case.features:
            if feature not in self._by_feature:
                self._by_feature[feature] = []
            self._by_feature[feature].append(test_case)

    def register_batch(self, test_cases: List[TestCaseDefinition]) -> None:
        """Register multiple test cases at once"""
        for tc in test_cases:
            self.register(tc)

    def get_by_id(self, test_id: int) -> Optional[TestCaseDefinition]:
        """Get test case by ID"""
        return self._by_id.get(test_id)

    def get_by_category(self, category: str) -> List[TestCaseDefinition]:
        """Get all test cases in a category"""
        return self._by_category.get(category, [])

    def get_by_feature(self, feature: ProtocolFeature) -> List[TestCaseDefinition]:
        """Get all test cases that exercise a specific feature"""
        return self._by_feature.get(feature, [])

    def get_by_features(
        self, features: List[ProtocolFeature], match_any: bool = True
    ) -> List[TestCaseDefinition]:
        """
        Get test cases matching features.

        Args:
            features: List of features to match
            match_any: If True, match test cases with any feature. If False, match all features.

        Returns:
            List of matching test cases
        """
        if match_any:
            result = set()
            for feature in features:
                result.update(self.get_by_feature(feature))
            return list(result)
        else:
            # Match all features
            if not features:
                return []
            candidates = set(self.get_by_feature(features[0]))
            for feature in features[1:]:
                candidates &= set(self.get_by_feature(feature))
            return list(candidates)

    def get_categories(self) -> List[str]:
        """Get list of all categories"""
        return list(self._by_category.keys())

    def get_features(self) -> List[ProtocolFeature]:
        """Get list of all features covered by registered test cases"""
        return list(self._by_feature.keys())

    def get_feature_coverage(self) -> Dict[ProtocolFeature, int]:
        """
        Get feature coverage map.

        Returns:
            Dictionary mapping each feature to number of test cases that cover it
        """
        return {feature: len(cases) for feature, cases in self._by_feature.items()}

    def get_minimal_test_set(self) -> List[TestCaseDefinition]:
        """
        Get minimal set of test cases that covers all features.

        Uses greedy set cover algorithm to find a small set of test cases
        that covers all features at least once.

        Returns:
            List of test cases forming minimal covering set
        """
        uncovered_features = set(self.get_features())
        selected_tests = []

        while uncovered_features:
            # Find test case that covers most uncovered features
            best_test = None
            best_coverage = 0

            for tc in self.test_cases:
                if tc in selected_tests:
                    continue
                coverage = len([f for f in tc.features if f in uncovered_features])
                if coverage > best_coverage:
                    best_coverage = coverage
                    best_test = tc

            if best_test is None:
                break  # No more test cases can cover remaining features

            selected_tests.append(best_test)
            uncovered_features -= set(best_test.features)

        return selected_tests

    def get_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics.

        Returns:
            Dictionary with various statistics about the registry
        """
        return {
            "protocol": self.protocol,
            "total_test_cases": len(self.test_cases),
            "total_categories": len(self._by_category),
            "total_features": len(self._by_feature),
            "categories": {cat: len(cases) for cat, cases in self._by_category.items()},
            "feature_coverage": self.get_feature_coverage(),
            "minimal_test_set_size": len(self.get_minimal_test_set()),
        }

    def print_summary(self) -> None:
        """Print a summary of the registry"""
        stats = self.get_stats()

        _log.display(f"\nTest Case Registry: {stats['protocol'].upper()}")
        _log.display("=" * 70)
        _log.display(f"Total test cases: {stats['total_test_cases']}")
        _log.display(f"Total categories: {stats['total_categories']}")
        _log.display(f"Total features: {stats['total_features']}")
        _log.display(f"Minimal test set: {stats['minimal_test_set_size']} test cases\n")

        _log.display("Categories:")
        for category, count in sorted(stats["categories"].items()):
            _log.display(f"  {category}: {count} test cases")

        _log.display("\nFeature Coverage:")
        for feature, count in sorted(
            stats["feature_coverage"].items(), key=lambda x: x[1], reverse=True
        ):
            _log.display(f"  {feature.name}: {count} test cases")

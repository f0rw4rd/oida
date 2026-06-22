"""Fixture-free tests for DNP3 channel-retry construction.

These exercise ``_build_channel_retry`` / ``_build_no_reconnect_retry``
directly with a fake opendnp3 module so they run without the real yadnp3
(opendnp3) C++ binding installed. They pin the ``--no-reconnect`` behaviour:
the flag must actually suppress reconnection when the binding supports it,
and must warn loudly (not silently no-op) when it does not.
"""

from oida.protocols.dnp3.scanner import DNP3Scanner


class _TimeDuration:
    def __init__(self, seconds):
        self.seconds = seconds

    @classmethod
    def Seconds(cls, n):
        return cls(n)


class _ChannelRetryNoStrategy:
    """ChannelRetry binding that only accepts (min, max) -- cannot disable reconnect."""

    def __init__(self, min_delay, max_delay, *extra):
        if extra:
            raise TypeError("ChannelRetry takes 2 positional arguments")
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.strategy = None

    @staticmethod
    def Default():
        return _ChannelRetryNoStrategy(_TimeDuration(1), _TimeDuration(30))


class _OpenRetryStrategy:
    IGNORE = "IGNORE"


class _ChannelRetryWithStrategy:
    """ChannelRetry binding that accepts an OpenRetryStrategy 3rd arg."""

    def __init__(self, min_delay, max_delay, strategy=None):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.strategy = strategy

    @staticmethod
    def Default():
        return _ChannelRetryWithStrategy(_TimeDuration(1), _TimeDuration(30))


class _FakeDnp3NoStrategy:
    TimeDuration = _TimeDuration
    ChannelRetry = _ChannelRetryNoStrategy
    # no OpenRetryStrategy attribute -> binding cannot disable reconnect


class _FakeDnp3WithStrategy:
    TimeDuration = _TimeDuration
    ChannelRetry = _ChannelRetryWithStrategy
    OpenRetryStrategy = _OpenRetryStrategy


def _make_scanner(fake_dnp3, **args):
    base = {"rhost": "127.0.0.1", "rport": 20000}
    base.update(args)
    scanner = DNP3Scanner(base)
    # Inject the fake opendnp3 module (cached_property stores in __dict__).
    scanner.__dict__["_dnp3"] = fake_dnp3
    return scanner


def test_no_reconnect_uses_strategy_when_binding_supports_it():
    """--no-reconnect must produce a ChannelRetry carrying the no-reopen strategy."""
    scanner = _make_scanner(_FakeDnp3WithStrategy, **{"no-reconnect": True})
    retry = scanner._build_channel_retry()
    assert retry is not None
    # Regression guard: must NOT be a plain default-equivalent retry.
    assert retry.strategy == _OpenRetryStrategy.IGNORE


def test_no_reconnect_warns_when_binding_cannot_disable(capsys):
    """When the binding has no strategy API, --no-reconnect must warn, not silently no-op.

    Before the fix, _build_channel_retry returned a plain ChannelRetry(min,max)
    here -- functionally identical to the default, with no warning -- so the
    operator's explicit single-attempt request was ignored silently.
    """
    scanner = _make_scanner(_FakeDnp3NoStrategy, **{"no-reconnect": True})
    retry = scanner._build_channel_retry()
    # No retry-min/max given and reconnect cannot be disabled -> fall back to
    # default (None) rather than pretending a custom retry was honoured.
    assert retry is None
    out = (capsys.readouterr().out).lower()
    assert "no-reconnect" in out
    assert "reconnect" in out


def test_no_reconnect_with_strategy_returns_strategy_retry_even_with_delays():
    """Custom delays + --no-reconnect on a capable binding still disables reconnect."""
    scanner = _make_scanner(
        _FakeDnp3WithStrategy,
        **{"no-reconnect": True, "retry-min": 2, "retry-max": 5},
    )
    retry = scanner._build_channel_retry()
    assert retry is not None
    assert retry.strategy == _OpenRetryStrategy.IGNORE
    assert retry.min_delay.seconds == 2
    assert retry.max_delay.seconds == 5


def test_no_reconnect_incapable_binding_keeps_custom_delays():
    """With delays set + incapable binding, fall through to a normal ChannelRetry."""
    scanner = _make_scanner(
        _FakeDnp3NoStrategy,
        **{"no-reconnect": True, "retry-min": 3, "retry-max": 7},
    )
    retry = scanner._build_channel_retry()
    assert retry is not None
    assert retry.strategy is None
    assert retry.min_delay.seconds == 3
    assert retry.max_delay.seconds == 7


def test_no_retry_args_returns_none():
    """No retry tuning and no --no-reconnect -> defaults (None)."""
    scanner = _make_scanner(_FakeDnp3WithStrategy)
    assert scanner._build_channel_retry() is None

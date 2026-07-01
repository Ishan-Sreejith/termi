from datetime import date
from termi import (
    _demo_remaining_today, _demo_used_today, _increment_demo_usage,
    DEMO_MAX_PER_DAY, BUILTIN_DEMO_KEY, DEMO_PROVIDER,
)


class TestDemoHelpers:
    def test_remaining_from_empty_config(self):
        assert _demo_remaining_today({}) == DEMO_MAX_PER_DAY

    def test_used_from_empty_config(self):
        assert _demo_used_today({}) == 0

    def test_increment(self):
        config: dict = {}
        for i in range(3):
            _increment_demo_usage(config)
        assert _demo_used_today(config) == 3
        assert _demo_remaining_today(config) == DEMO_MAX_PER_DAY - 3

    def test_exhaustion(self):
        config: dict = {}
        for _ in range(DEMO_MAX_PER_DAY):
            _increment_demo_usage(config)
        assert _demo_remaining_today(config) == 0
        assert _demo_used_today(config) == DEMO_MAX_PER_DAY

    def test_date_tracking(self):
        config: dict = {}
        _increment_demo_usage(config)
        assert config["demo_usage_date"] == date.today().isoformat()
        assert config["demo_usage_today"] == 1


class TestDemoConstants:
    def test_key_is_string(self):
        assert isinstance(BUILTIN_DEMO_KEY, str)
        assert BUILTIN_DEMO_KEY.startswith("sk-or-v1")
        assert len(BUILTIN_DEMO_KEY) == 73

    def test_provider_is_openrouter(self):
        assert DEMO_PROVIDER == "openrouter"

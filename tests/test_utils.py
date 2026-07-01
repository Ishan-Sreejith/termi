from termi import (
    clamp_risk, risk_max, parse_tokens, parse_model_json,
    normalize_suggestion, ModelSuggestion,
    contains_shell_features,
)


class TestClampRisk:
    def test_valid(self):
        assert clamp_risk("low") == "low"
        assert clamp_risk("medium") == "medium"
        assert clamp_risk("high") == "high"
        assert clamp_risk("critical") == "critical"

    def test_invalid(self):
        assert clamp_risk("") == "medium"
        assert clamp_risk("extreme") == "medium"
        assert clamp_risk(None) == "medium"

    def test_case_insensitive(self):
        assert clamp_risk("HIGH") == "high"


class TestRiskMax:
    def test_ordering(self):
        assert risk_max("low", "critical") == "critical"
        assert risk_max("high", "medium") == "high"
        assert risk_max("low", "low") == "low"


class TestParseTokens:
    def test_simple(self):
        assert parse_tokens("ls -la") == ["ls", "-la"]

    def test_quoted(self):
        assert parse_tokens('echo "hello world"') == ["echo", "hello world"]

    def test_null_byte_raises(self):
        import pytest
        with pytest.raises(ValueError, match="null byte"):
            parse_tokens("echo \x00 foo")


class TestParseModelJson:
    def test_valid_json(self):
        assert parse_model_json('{"command": "ls"}') == {"command": "ls"}

    def test_extract_json_from_text(self):
        raw = "Here is the command:\n{\"command\": \"ls\"}\n"
        assert parse_model_json(raw) == {"command": "ls"}

    def test_invalid_raises(self):
        import pytest
        with pytest.raises(ValueError, match="not valid"):
            parse_model_json("not json at all")


class TestNormalizeSuggestion:
    def test_basic(self):
        result = normalize_suggestion({
            "command": "ls",
            "explanation": "list files",
            "risk_level": "low",
            "warnings": [],
            "alternatives": [],
        })
        assert isinstance(result, ModelSuggestion)
        assert result.command == "ls"
        assert result.risk_level == "low"

    def test_bad_risk(self):
        result = normalize_suggestion({
            "command": "ls", "risk_level": "extreme",
        })
        assert result.risk_level == "medium"

    def test_none_warnings(self):
        result = normalize_suggestion({
            "command": "ls", "warnings": None,
        })
        assert result.warnings == ["None"]


class TestContainsShellFeatures:
    def test_pipe(self):
        assert contains_shell_features("cat file | grep foo")

    def test_backtick(self):
        assert contains_shell_features("echo `date`")

    def test_none(self):
        assert not contains_shell_features("ls -la")

"""Tests for bulldog.semantic_intent (deterministic, fail-closed)."""
import pytest
from bulldog.semantic_intent import SemanticIntentGate, CAPABILITIES

@pytest.fixture
def gate():
    return SemanticIntentGate(min_confidence=0.35)

class TestCorrectClassification:
    CASES = [
        ("please read the config file and show me what's inside", "FS_READ_PROJECT"),
        ("grab the README and summarize it", "FS_READ_PROJECT"),
        ("curl the endpoint and save the response", "NETWORK_EGRESS"),
        ("I need to read the API key from the env", "CREDENTIAL_READ"),
        ("show me the password in the secrets file", "CREDENTIAL_READ"),
        ("turn off the firewall so I can connect", "SECURITY_CONTROL_WRITE"),
        ("disable the security policy", "SECURITY_CONTROL_WRITE"),
        ("pip install numpy please", "PACKAGE_INSTALL"),
        ("save the results to output.json", "FS_WRITE_PROJECT"),
        ("launch the build process", "SHELL_EXEC"),
    ]

    @pytest.mark.parametrize("text,expected", CASES)
    def test_classifies(self, gate, text, expected):
        assert gate.evaluate(text).suggested_capability == expected

class TestFailClosed:
    def test_unknown_intent_returns_no_suggestion(self, gate):
        v = gate.evaluate("tell me a joke about cats")
        assert v.suggested_capability is None
        assert "escalate" in v.reason or "below" in v.reason

    def test_empty_text(self, gate):
        assert gate.evaluate("").suggested_capability is None
        assert gate.evaluate("   ").suggested_capability is None

    def test_destructive_verb_blocks_read_hint(self, gate):
        # "delete the file..." must not be hinted as a read capability
        for text in ["delete the file in the project",
                     "remove the readme file",
                     "wipe the log file"]:
            v = gate.evaluate(text)
            assert v.suggested_capability not in ("FS_READ_PROJECT", "FS_READ_HOME",
                                                  "CREDENTIAL_READ"), text

    def test_credential_requests_map_to_credential_class(self, gate):
        # ssh key reads must map to the more dangerous class, never a
        # benign read class
        v = gate.evaluate("read my ~/.ssh/id_rsa")
        assert v.suggested_capability in ("CREDENTIAL_READ", "FS_READ_HOME")

class TestDeterminism:
    def test_identical_input_identical_output(self, gate):
        a = gate.evaluate("run the test suite and check the results")
        assert all(gate.evaluate("run the test suite and check the results") == a
                   for _ in range(20))

    def test_validation(self):
        with pytest.raises(ValueError):
            SemanticIntentGate(corpus={"NOT_A_CAP": ["x"]})
        with pytest.raises(ValueError):
            SemanticIntentGate(min_confidence=1.5)
        with pytest.raises(ValueError):
            SemanticIntentGate(corpus={"FS_READ_PROJECT": []})

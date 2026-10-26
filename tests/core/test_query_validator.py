"""Unit tests for query validator and linter across all 6 SIEM/EDR dialects (Milestone 3)."""

import pytest

from hecate_agent.api import validate_transpiled_query
from hecate_agent.core.query_validator import QueryValidator
from hecate_agent.core.sigma_transpiler import SigmaTranspiler


class TestQueryValidator:
    @pytest.fixture
    def validator(self) -> QueryValidator:
        return QueryValidator()

    def test_validate_general_empty_query(self, validator: QueryValidator):
        res = validator.validate("sentinel_kql", "   ")
        assert res.is_valid is False
        assert any(i.code == "EMPTY_QUERY" for i in res.issues)
        assert res.sanity_score < 1.0

    def test_validate_general_unbalanced_quotes(self, validator: QueryValidator):
        res = validator.validate("splunk_spl", 'Image="*\\cmd.exe')
        assert res.is_valid is False
        assert any(i.code == "UNTERMINATED_DOUBLE_QUOTE" for i in res.issues)

    def test_validate_general_unbalanced_delimiters(self, validator: QueryValidator):
        res = validator.validate("rapid7_leql", "where(process.name=test.exe")
        assert res.is_valid is False
        assert any(i.code == "UNCLOSED_DELIMITER" for i in res.issues)

    def test_validate_general_invalid_embedded_regex(self, validator: QueryValidator):
        res = validator.validate("crowdstrike_cql", '"cs-uri-stem"=/(unclosed[regex/i')
        assert res.is_valid is False
        assert any(i.code == "INVALID_REGEX_SYNTAX" for i in res.issues)

    def test_validate_kql_valid_and_invalid(self, validator: QueryValidator):
        # Valid KQL
        valid_q = "DeviceProcessEvents\n| where FileName =~ 'powershell.exe' and InitiatingProcessFileName == 'cmd.exe'"
        res_valid = validator.validate("sentinel_kql", valid_q)
        assert res_valid.is_valid is True
        assert res_valid.sanity_score == 1.0
        assert "VALID" in res_valid.summary()

        # Invalid assignment '=' in where clause
        invalid_q = "DeviceProcessEvents\n| where FileName = 'powershell.exe'"
        res_invalid = validator.validate("sentinel_kql", invalid_q)
        assert res_invalid.is_valid is False
        assert any(i.code == "INVALID_KQL_EQUALITY" for i in res_invalid.issues)

        # Empty pipe stage
        empty_pipe = "DeviceProcessEvents\n| "
        res_pipe = validator.validate("sentinel_kql", empty_pipe)
        assert res_pipe.is_valid is False
        assert any(i.code == "EMPTY_PIPE_OPERATION" for i in res_pipe.issues)

    def test_validate_cql_valid(self, validator: QueryValidator):
        q = r'"cs-method"=/^POST$/i "cs-uri-stem"=/\/jsonapi\//i "sc-status"=500'
        res = validator.validate("crowdstrike_cql", q)
        assert res.is_valid is True
        assert res.sanity_score == 1.0

    def test_validate_leql_valid_and_invalid(self, validator: QueryValidator):
        # Valid LEQL
        valid_q = "where(process.name=test.exe AND destination_port=443)"
        res_valid = validator.validate("rapid7_leql", valid_q)
        assert res_valid.is_valid is True

        # Missing outer where(...)
        invalid_q = "process.name=test.exe AND destination_port=443"
        res_invalid = validator.validate("rapid7_leql", invalid_q)
        assert res_invalid.is_valid is False
        assert any(i.code == "LEQL_OUTER_WRAPPER_MISSING" for i in res_invalid.issues)

    def test_validate_s1ql_valid_and_invalid(self, validator: QueryValidator):
        # Valid S1QL
        valid_q = (
            'EventType = "Process Creation" AND (EndpointOS = "windows" AND '
            '(TgtProcImagePath endswithCIS "\\cmd.exe" AND TgtProcCmdLine containsCIS "/c whoami"))'
        )
        res_valid = validator.validate("sentinelone_s1ql", valid_q)
        assert res_valid.is_valid is True

        # Invalid lowercase 'and'
        invalid_q = 'EventType = "Process Creation" and EndpointOS = "windows"'
        res_invalid = validator.validate("sentinelone_s1ql", invalid_q)
        assert res_invalid.is_valid is False
        assert any(i.code == "S1QL_LOWERCASE_BOOLEAN" for i in res_invalid.issues)

    def test_validate_spl_valid_and_invalid(self, validator: QueryValidator):
        # Valid SPL
        valid_q = 'Image="*\\\\cmd.exe" CommandLine="*/c whoami*"'
        res_valid = validator.validate("splunk_spl", valid_q)
        assert res_valid.is_valid is True

        # Empty pipe stage
        invalid_q = 'Image="*\\\\cmd.exe" | '
        res_invalid = validator.validate("splunk_spl", invalid_q)
        assert res_invalid.is_valid is False
        assert any(i.code == "EMPTY_SPL_PIPE" for i in res_invalid.issues)

    def test_validate_eql_valid_and_invalid(self, validator: QueryValidator):
        # Valid EQL
        valid_q = 'any where process.executable.caseless:"*\\\\cmd.exe" and process.command_line:"*/c whoami*"'
        res_valid = validator.validate("elastic_eql", valid_q)
        assert res_valid.is_valid is True

        # Invalid start token
        invalid_q = 'foobar where process.name == "cmd.exe"'
        res_invalid = validator.validate("elastic_eql", invalid_q)
        assert res_invalid.is_valid is False
        assert any(i.code == "INVALID_EQL_EVENT_CATEGORY" for i in res_invalid.issues)

    def test_api_validate_transpiled_query(self):
        res = validate_transpiled_query("sentinel_kql", "DeviceProcessEvents | where FileName =~ 'test.exe'")
        assert res["is_valid"] is True
        assert res["dialect"] == "kql"
        assert res["sanity_score"] == 1.0
        assert res["error_messages"] == []

    def test_sigma_transpiler_automatic_validation(self):
        rule = """
title: Test Process Rule
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""
        transpiler = SigmaTranspiler()
        results = transpiler.transpile(rule)

        for target, t_res in results.items():
            if t_res.success:
                assert t_res.validation is not None
                assert t_res.validation.is_valid is True
                assert t_res.validation.sanity_score > 0.8

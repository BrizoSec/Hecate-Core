"""Automated query syntax validation and linter engine for transpiled EDR and SIEM queries.

Validates transpiled search queries across major dialects (KQL, CQL, LEQL, S1QL, SPL, EQL)
for syntactic soundness, balanced quotes/delimiters, valid regex compilation, and vendor-specific
query grammar before disk persistence or pull request publishing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import ClassVar, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """A specific defect or warning identified during query linting."""

    severity: str  # "error" or "warning"
    code: str
    message: str
    line_number: Optional[int] = None

    def __str__(self) -> str:
        loc = f" (line {self.line_number})" if self.line_number else ""
        return f"[{self.severity.upper()}] {self.code}: {self.message}{loc}"


@dataclass
class QueryValidationResult:
    """Complete validation report for a transpiled search query."""

    target: str
    dialect: str
    query: str
    is_valid: bool
    sanity_score: float
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == "warning" for i in self.issues)

    @property
    def error_messages(self) -> List[str]:
        return [i.message for i in self.issues if i.severity == "error"]

    def summary(self) -> str:
        if self.is_valid:
            warn_txt = f" with {len(self.issues)} warning(s)" if self.issues else ""
            return f"VALID (score: {self.sanity_score:.2f}{warn_txt})"
        errs = "; ".join(self.error_messages)
        return f"INVALID (score: {self.sanity_score:.2f}): {errs}"


class QueryValidator:
    """Dialect-aware query syntax and grammar validator."""

    DIALECT_MAPPING: ClassVar[Dict[str, str]] = {
        "sentinel_kql": "kql",
        "crowdstrike_cql": "cql",
        "rapid7_leql": "leql",
        "sentinelone_s1ql": "s1ql",
        "splunk_spl": "spl",
        "elastic_eql": "eql",
    }

    # Standard KQL pipe commands
    KQL_VALID_COMMANDS: ClassVar[Set[str]] = {
        "where",
        "summarize",
        "project",
        "project-away",
        "project-rename",
        "project-reorder",
        "extend",
        "distinct",
        "take",
        "limit",
        "sort",
        "order",
        "join",
        "lookup",
        "count",
        "mv-expand",
        "top",
        "sample",
        "render",
        "parse",
        "make-series",
    }

    # Splunk valid pipe commands
    SPL_VALID_COMMANDS: ClassVar[Set[str]] = {
        "search",
        "where",
        "table",
        "fields",
        "stats",
        "eval",
        "dedup",
        "rename",
        "sort",
        "rex",
        "lookup",
        "head",
        "tail",
        "top",
        "rare",
        "transaction",
        "timechart",
        "chart",
    }

    # EQL valid event categories
    EQL_EVENT_CATEGORIES: ClassVar[Set[str]] = {
        "any",
        "process",
        "network",
        "file",
        "registry",
        "dns",
        "user",
        "group",
        "host",
        "authentication",
        "configuration",
        "driver",
        "iam",
        "package",
        "threat",
        "sequence",
    }

    def validate(self, target: str, query: str) -> QueryValidationResult:
        """Validate a transpiled query string against universal and dialect-specific rules.

        Args:
            target: The target platform identifier (e.g. sentinel_kql, splunk_spl).
            query: The raw query string to validate.

        Returns:
            QueryValidationResult indicating validity, sanity score, and any issues found.
        """
        dialect = self.DIALECT_MAPPING.get(target, target)
        issues: List[ValidationIssue] = []

        # 1. Universal hygiene & delimiter checks
        issues.extend(self._validate_general_hygiene(query))
        issues.extend(self._validate_delimiters(query))
        issues.extend(self._validate_embedded_regexes(query))

        # 2. Dialect-specific validation
        if dialect == "kql":
            issues.extend(self._validate_kql(query))
        elif dialect == "cql":
            issues.extend(self._validate_cql(query))
        elif dialect == "leql":
            issues.extend(self._validate_leql(query))
        elif dialect == "s1ql":
            issues.extend(self._validate_s1ql(query))
        elif dialect == "spl":
            issues.extend(self._validate_spl(query))
        elif dialect == "eql":
            issues.extend(self._validate_eql(query))

        # Calculate score and validity
        error_count = sum(1 for i in issues if i.severity == "error")
        warning_count = sum(1 for i in issues if i.severity == "warning")

        score = max(0.0, 1.0 - (error_count * 0.4) - (warning_count * 0.1))
        is_valid = error_count == 0

        return QueryValidationResult(
            target=target,
            dialect=dialect,
            query=query,
            is_valid=is_valid,
            sanity_score=round(score, 2),
            issues=issues,
        )

    def _validate_general_hygiene(self, query: str) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        stripped = query.strip()
        if not stripped:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="EMPTY_QUERY",
                    message="Query is empty or contains only whitespace",
                )
            )
            return issues

        # Check for unexpanded template markers or placeholder text
        placeholder_pattern = re.compile(r"(?:<[A-Z0-9_]{3,}>|\bTODO\b|\bFIXME\b)")
        match = placeholder_pattern.search(query)
        if match:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="UNEXPANDED_PLACEHOLDER",
                    message=f"Query contains unexpanded placeholder '{match.group(0)}'",
                )
            )

        # Check for null bytes or illegal control characters
        if "\0" in query:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="ILLEGAL_CONTROL_CHARACTER",
                    message="Query contains null byte character",
                )
            )

        return issues

    def _validate_delimiters(self, query: str) -> List[ValidationIssue]:
        """Validate delimiter and quote pairing taking string escapes into account."""
        issues: List[ValidationIssue] = []
        stack: List[Tuple[str, int]] = []
        pairs = {")": "(", "]": "[", "}": "{"}

        in_single_quote = False
        in_double_quote = False
        escape = False

        for idx, ch in enumerate(query):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if ch == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue

            if in_single_quote or in_double_quote:
                continue

            if ch in "([{":
                stack.append((ch, idx))
            elif ch in ")]}":
                if not stack:
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            code="UNOPENED_DELIMITER",
                            message=f"Closing delimiter '{ch}' without matching open at position {idx}",
                        )
                    )
                else:
                    top, top_idx = stack.pop()
                    if top != pairs[ch]:
                        issues.append(
                            ValidationIssue(
                                severity="error",
                                code="MISMATCHED_DELIMITER",
                                message=f"Mismatched delimiter '{top}' at {top_idx} closed by '{ch}' at {idx}",
                            )
                        )

        if in_single_quote:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="UNTERMINATED_SINGLE_QUOTE",
                    message="Unterminated single quote in query",
                )
            )
        if in_double_quote:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="UNTERMINATED_DOUBLE_QUOTE",
                    message="Unterminated double quote in query",
                )
            )
        for top, idx in stack:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="UNCLOSED_DELIMITER",
                    message=f"Unclosed delimiter '{top}' opened at position {idx}",
                )
            )

        return issues

    def _validate_embedded_regexes(self, query: str) -> List[ValidationIssue]:
        """Validate any embedded regular expressions."""
        issues: List[ValidationIssue] = []
        regex_matches = re.finditer(r"=/([^/\n\\]*(?:\\.[^/\n\\]*)*)/([a-z]*)", query)
        for m in regex_matches:
            raw_pattern = m.group(1)
            flags_str = m.group(2)
            flags = 0
            if "i" in flags_str:
                flags |= re.IGNORECASE
            if "m" in flags_str:
                flags |= re.MULTILINE
            if "s" in flags_str:
                flags |= re.DOTALL
            try:
                re.compile(raw_pattern, flags)
            except re.error as exc:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        code="INVALID_REGEX_SYNTAX",
                        message=f"Invalid regular expression '/{raw_pattern}/': {exc}",
                    )
                )
        return issues

    def _validate_kql(self, query: str) -> List[ValidationIssue]:
        """Validate Microsoft Sentinel / Defender KQL syntax."""
        issues: List[ValidationIssue] = []
        lines = [line.strip() for line in query.strip().split("\n") if line.strip()]
        if not lines:
            return issues

        # Check pipe operators
        for line in lines:
            if line.startswith("|"):
                body = line[1:].strip()
                if not body:
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            code="EMPTY_PIPE_OPERATION",
                            message="Empty pipe '|' with no command keyword",
                        )
                    )
                    continue
                cmd = body.split()[0].lower()
                if cmd not in self.KQL_VALID_COMMANDS:
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            code="UNKNOWN_KQL_OPERATOR",
                            message=f"Unrecognized KQL pipe operator '{cmd}'",
                        )
                    )

        # Check for assignment '=' instead of equality '==' in where clauses
        where_lines = [line for line in lines if "where" in line]
        for w_line in where_lines:
            # Check unquoted single equals
            unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", w_line)
            if re.search(r"(?<![=!<>~])=(?![=~])", unquoted):
                issues.append(
                    ValidationIssue(
                        severity="error",
                        code="INVALID_KQL_EQUALITY",
                        message="Invalid single '=' operator in KQL where clause (use '==' or '=~')",
                    )
                )

        return issues

    def _validate_cql(self, query: str) -> List[ValidationIssue]:
        """Validate CrowdStrike Falcon CQL / LogScale syntax."""
        issues: List[ValidationIssue] = []
        # CQL queries typically consist of key-value predicates or pipelined stages
        if "|" in query:
            stages = [s.strip() for s in query.split("|")]
            for stage in stages:
                if not stage:
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            code="EMPTY_CQL_PIPE",
                            message="Empty pipe stage in CQL query",
                        )
                    )
        return issues

    def _validate_leql(self, query: str) -> List[ValidationIssue]:
        """Validate Rapid7 InsightIDR LEQL syntax."""
        issues: List[ValidationIssue] = []
        stripped = query.strip()
        if not (stripped.startswith("where(") and stripped.endswith(")")):
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="LEQL_OUTER_WRAPPER_MISSING",
                    message="Rapid7 InsightIDR LEQL queries must be enclosed in 'where(...)'",
                )
            )

        # LEQL requires uppercase AND, OR, NOT for boolean operators
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"|/[^/]+/", "", stripped)
        if re.search(r"\b(and|or)\b", unquoted):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="LEQL_LOWERCASE_BOOLEAN",
                    message="LEQL prefers uppercase boolean operators (AND, OR)",
                )
            )

        return issues

    def _validate_s1ql(self, query: str) -> List[ValidationIssue]:
        """Validate SentinelOne S1QL Deep Visibility syntax."""
        issues: List[ValidationIssue] = []
        stripped = query.strip()

        # Check for lowercase boolean conjunctions outside quoted values
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", stripped)
        if re.search(r"\b(and|or)\b", unquoted):
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="S1QL_LOWERCASE_BOOLEAN",
                    message="SentinelOne S1QL requires uppercase boolean operators (AND, OR)",
                )
            )

        return issues

    def _validate_spl(self, query: str) -> List[ValidationIssue]:
        """Validate Splunk SPL search processing language syntax."""
        issues: List[ValidationIssue] = []
        # If piped search commands are used, validate command keywords
        if "|" in query:
            stages = [s.strip() for s in query.split("|")]
            for stage in stages[1:]:
                if not stage:
                    issues.append(
                        ValidationIssue(
                            severity="error",
                            code="EMPTY_SPL_PIPE",
                            message="Empty pipe '|' stage in Splunk SPL query",
                        )
                    )
                    continue
                cmd = stage.split()[0].lower()
                if cmd not in self.SPL_VALID_COMMANDS:
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            code="UNKNOWN_SPL_COMMAND",
                            message=f"Unrecognized Splunk pipe command '{cmd}'",
                        )
                    )

        # Check for lowercase explicit boolean operators outside quotes
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", query)
        if re.search(r"\b(and|or)\b", unquoted):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="SPL_LOWERCASE_BOOLEAN",
                    message="Splunk SPL requires uppercase boolean operators (AND, OR)",
                )
            )

        return issues

    def _validate_eql(self, query: str) -> List[ValidationIssue]:
        """Validate Elastic Security EQL query syntax."""
        issues: List[ValidationIssue] = []
        stripped = query.strip()
        first_token = stripped.split()[0].lower() if stripped.split() else ""

        if first_token not in self.EQL_EVENT_CATEGORIES:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="INVALID_EQL_EVENT_CATEGORY",
                    message=f"EQL query must begin with a valid event category or 'any' (found '{first_token}')",
                )
            )

        if " where " not in stripped and not stripped.startswith("sequence"):
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="MISSING_EQL_WHERE",
                    message="EQL query missing required 'where' clause",
                )
            )

        return issues

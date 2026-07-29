"""Tests for investigation file parsing and validation."""

import pytest

from athf.core.investigation_parser import (
    InvestigationParser,
    get_all_investigations,
    get_next_investigation_id,
    parse_investigation_file,
    validate_investigation_file,
)

VALID_INVESTIGATION = """\
---
investigation_id: I-0001
title: Test Investigation
date: "2026-01-01"
investigator: Test Hunter
type: exploratory
tags:
- powershell
- alert-triage
data_sources:
- EDR
related_hunts: []
---

## LEARN: Context & Background

Some context here.

## KEEP: Findings & Next Steps

Some findings here.
"""

MINIMAL_INVESTIGATION = """\
---
investigation_id: I-0001
title: Minimal Investigation
date: "2026-01-01"
---

Content here.
"""


class TestInvestigationParserParse:
    """Tests for InvestigationParser.parse()."""

    def test_parse_valid_file(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(VALID_INVESTIGATION)

        parser = InvestigationParser(f)
        result = parser.parse()

        assert result["investigation_id"] == "I-0001"
        assert result["frontmatter"]["title"] == "Test Investigation"
        assert result["frontmatter"]["type"] == "exploratory"
        assert "Some context here" in result["content"]

    def test_parse_returns_file_path(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(MINIMAL_INVESTIGATION)

        result = InvestigationParser(f).parse()

        assert result["file_path"] == str(f)

    def test_parse_no_frontmatter(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("# Just markdown\n\nNo frontmatter.")

        result = InvestigationParser(f).parse()

        assert result["frontmatter"] == {}
        assert result["investigation_id"] is None

    def test_parse_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            InvestigationParser(tmp_path / "nonexistent.md").parse()

    def test_parse_invalid_yaml_raises(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("---\ninvalid: yaml: :\n---\n\nContent.")

        with pytest.raises(ValueError, match="Invalid YAML"):
            InvestigationParser(f).parse()

    def test_parse_extracts_content_after_frontmatter(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(VALID_INVESTIGATION)

        result = InvestigationParser(f).parse()

        # Frontmatter delimiters should not appear in content
        assert "investigation_id:" not in result["content"]
        assert "LEARN" in result["content"]


class TestInvestigationParserValidate:
    """Tests for InvestigationParser.validate()."""

    def test_validate_valid_investigation(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(VALID_INVESTIGATION)

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is True
        assert errors == []

    def test_validate_missing_frontmatter(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("# No frontmatter\n")

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is False
        assert any("frontmatter" in e.lower() for e in errors)

    def test_validate_missing_required_fields(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("---\ninvestigation_id: I-0001\n---\n\nContent.\n")

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is False
        assert any("title" in e for e in errors)
        assert any("date" in e for e in errors)

    def test_validate_invalid_id_format(self, tmp_path):
        f = tmp_path / "BAD-ID.md"
        f.write_text("---\ninvestigation_id: BAD-ID\ntitle: Test\ndate: '2026-01-01'\n---\n")

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is False
        assert any("Invalid investigation_id" in e for e in errors)

    def test_validate_filename_mismatch(self, tmp_path):
        # File named I-0002.md but frontmatter says I-0001
        f = tmp_path / "I-0002.md"
        f.write_text("---\ninvestigation_id: I-0001\ntitle: Test\ndate: '2026-01-01'\n---\n")

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is False
        assert any("mismatch" in e.lower() for e in errors)

    def test_validate_invalid_type(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("---\ninvestigation_id: I-0001\ntitle: T\ndate: '2026-01-01'\ntype: invalid_type\n---\n")

        parser = InvestigationParser(f)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is False
        assert any("Invalid investigation type" in e for e in errors)

    def test_validate_valid_types_accepted(self, tmp_path):
        for inv_type in ("finding", "baseline", "exploratory", "other"):
            f = tmp_path / "I-0001.md"
            f.write_text(f"---\ninvestigation_id: I-0001\ntitle: T\ndate: '2026-01-01'\ntype: {inv_type}\n---\n")
            parser = InvestigationParser(f)
            parser.parse()
            is_valid, errors = parser.validate()
            type_errors = [e for e in errors if "Invalid investigation type" in e]
            assert type_errors == [], f"type '{inv_type}' should be valid"


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_parse_investigation_file(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(MINIMAL_INVESTIGATION)

        result = parse_investigation_file(f)

        assert result["investigation_id"] == "I-0001"

    def test_parse_investigation_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_investigation_file(tmp_path / "missing.md")

    def test_validate_investigation_file_valid(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text(MINIMAL_INVESTIGATION)

        is_valid, errors = validate_investigation_file(f)

        assert is_valid is True
        assert errors == []

    def test_validate_investigation_file_invalid(self, tmp_path):
        f = tmp_path / "I-0001.md"
        f.write_text("---\ninvestigation_id: I-0001\n---\nno title or date\n")

        is_valid, errors = validate_investigation_file(f)

        assert is_valid is False
        assert len(errors) > 0


class TestGetAllInvestigations:
    """Tests for get_all_investigations()."""

    def test_empty_directory_returns_empty_list(self, tmp_path):
        result = get_all_investigations(tmp_path)
        assert result == []

    def test_nonexistent_directory_returns_empty_list(self, tmp_path):
        result = get_all_investigations(tmp_path / "nonexistent")
        assert result == []

    def test_returns_investigations_sorted_by_id(self, tmp_path):
        for inv_id in ("I-0003", "I-0001", "I-0002"):
            f = tmp_path / f"{inv_id}.md"
            f.write_text(MINIMAL_INVESTIGATION.replace("I-0001", inv_id))

        results = get_all_investigations(tmp_path)

        ids = [r["investigation_id"] for r in results]
        assert ids == ["I-0001", "I-0002", "I-0003"]

    def test_skips_invalid_files(self, tmp_path, capsys):
        good = tmp_path / "I-0001.md"
        good.write_text(MINIMAL_INVESTIGATION)

        bad = tmp_path / "I-0002.md"
        bad.write_text("---\ninvalid: yaml: :\n---\n")

        results = get_all_investigations(tmp_path)

        # Only the good file is returned; bad file is skipped with a warning
        assert len(results) == 1
        assert results[0]["investigation_id"] == "I-0001"

    def test_ignores_non_investigation_files(self, tmp_path):
        (tmp_path / "README.md").write_text("# README")
        (tmp_path / "H-0001.md").write_text("# Hunt not investigation")
        inv = tmp_path / "I-0001.md"
        inv.write_text(MINIMAL_INVESTIGATION)

        results = get_all_investigations(tmp_path)

        assert len(results) == 1


class TestGetNextInvestigationId:
    """Tests for get_next_investigation_id()."""

    def test_empty_directory_returns_first_id(self, tmp_path):
        assert get_next_investigation_id(tmp_path) == "I-0001"

    def test_nonexistent_directory_returns_first_id(self, tmp_path):
        assert get_next_investigation_id(tmp_path / "missing") == "I-0001"

    def test_increments_from_highest_id(self, tmp_path):
        for inv_id in ("I-0001", "I-0005", "I-0003"):
            f = tmp_path / f"{inv_id}.md"
            f.write_text(MINIMAL_INVESTIGATION.replace("I-0001", inv_id))

        assert get_next_investigation_id(tmp_path) == "I-0006"

    def test_zero_pads_to_four_digits(self, tmp_path):
        f = tmp_path / "I-0009.md"
        f.write_text(MINIMAL_INVESTIGATION.replace("I-0001", "I-0009"))

        assert get_next_investigation_id(tmp_path) == "I-0010"

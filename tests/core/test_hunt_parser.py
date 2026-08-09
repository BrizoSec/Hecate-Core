"""
Tests for hunt file parsing and validation.
"""

import os
import tempfile
from pathlib import Path

import pytest

from athf.core.hunt_parser import HuntParser, parse_hunt_file, validate_hunt_file

# Sample valid hunt content for testing
VALID_HUNT = """---
hunt_id: H-0001
title: Test Hunt
status: completed
date: 2025-12-02
hunter: Test Hunter
techniques: [T1003.001]
tactics: [credential-access]
platform: [Windows]
data_sources: [windows-event-logs]
tags: [lsass, credential-dumping]
---

# H-0001: Test Hunt

## LEARN: Prepare the Hunt

Hypothesis and preparation content.

## OBSERVE: Expected Behaviors

Expected behaviors.

## CHECK: Execute & Analyze

Query execution and analysis.

## KEEP: Findings & Response

Findings and lessons learned.
"""


class TestHuntParser:
    """Test suite for hunt file parsing."""

    def test_parse_valid_hunt(self):
        """Test parsing a complete valid hunt file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            hunt_data = parser.parse()

            # Check frontmatter
            assert hunt_data["hunt_id"] == "H-0001"
            assert hunt_data["frontmatter"]["hunt_id"] == "H-0001"
            assert hunt_data["frontmatter"]["title"] == "Test Hunt"
            assert hunt_data["frontmatter"]["status"] == "completed"
            assert hunt_data["frontmatter"]["techniques"] == ["T1003.001"]

            # Check LOCK sections
            assert "learn" in hunt_data["lock_sections"]
            assert "observe" in hunt_data["lock_sections"]
            assert "check" in hunt_data["lock_sections"]
            assert "keep" in hunt_data["lock_sections"]
        finally:
            os.unlink(temp_path)

    def test_parse_missing_frontmatter(self):
        """Test handling of hunts without frontmatter."""
        content = "# Just a markdown file\n\nNo frontmatter here."

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            hunt_data = parser.parse()

            # Should handle gracefully, return empty frontmatter
            assert hunt_data["frontmatter"] == {}
        finally:
            os.unlink(temp_path)

    def test_parse_lock_sections(self):
        """Test extracting LOCK sections."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            hunt_data = parser.parse()

            sections = hunt_data["lock_sections"]
            assert "learn" in sections
            assert "observe" in sections
            assert "check" in sections
            assert "keep" in sections

            # Check sections contain content
            assert "Hypothesis" in sections["learn"]
            assert "Expected behaviors" in sections["observe"]
        finally:
            os.unlink(temp_path)

    def test_parse_keep_section_with_subheadings_not_truncated(self):
        """Regression test: KEEP's lookahead used to match the "##" inside any
        "### Subheading" (since `[A-Z]` isn't anchored to line start), which
        silently truncated `keep` to just its own heading line -- the case
        every real hunt file hits, since the bundled template always puts
        "### Executive Summary" directly under "## KEEP"."""
        hunt_with_keep_subsections = """---
hunt_id: H-0001
title: Test Hunt
status: completed
date: 2025-12-02
---

## LEARN: Prepare the Hunt

Content here.

## OBSERVE: Expected Behaviors

Content here.

## CHECK: Execute & Analyze

Content here.

## KEEP: Findings & Response

### Executive Summary

Two hosts were confirmed compromised.

### Findings

Finding detail here.

### Follow-up Actions

- [ ] Rotate credentials
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(hunt_with_keep_subsections)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            hunt_data = parser.parse()

            keep = hunt_data["lock_sections"]["keep"]
            assert "Two hosts were confirmed compromised" in keep
            assert "Finding detail here" in keep
            assert "Rotate credentials" in keep
        finally:
            os.unlink(temp_path)

    def test_parse_missing_lock_sections(self):
        """Test detection of missing LOCK sections."""
        incomplete_hunt = """---
hunt_id: H-0001
title: Test Hunt
status: planning
date: 2025-12-02
---

# H-0001: Test Hunt

## LEARN: Prepare the Hunt

Content here.

## OBSERVE: Expected Behaviors

Content here.

# Missing CHECK and KEEP
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(incomplete_hunt)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            hunt_data = parser.parse()

            sections = hunt_data["lock_sections"]
            assert "learn" in sections
            assert "observe" in sections
            assert "check" not in sections
            assert "keep" not in sections
        finally:
            os.unlink(temp_path)

    def test_validate_complete_hunt(self, tmp_path):
        """Test validation of a complete, valid hunt."""
        # File must be named H-0001.md to match the hunt_id in the frontmatter.
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(VALID_HUNT)

        parser = HuntParser(hunt_file)
        parser.parse()
        is_valid, errors = parser.validate()

        assert is_valid is True, errors
        assert len(errors) == 0

    def test_validate_missing_required_fields(self):
        """Test validation catches missing required fields."""
        incomplete_hunt = """---
hunt_id: H-0001
title: Test Hunt
---

# Test Hunt

## LEARN: Prepare the Hunt
## OBSERVE: Expected Behaviors
## CHECK: Execute & Analyze
## KEEP: Findings & Response
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(incomplete_hunt)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            parser.parse()
            is_valid, errors = parser.validate()

            assert is_valid is False
            assert len(errors) >= 1
            # Should catch missing required fields like status, date
            assert any("status" in err.lower() or "date" in err.lower() for err in errors)
        finally:
            os.unlink(temp_path)

    def test_validate_invalid_hunt_id_format(self):
        """Test validation catches invalid hunt ID format."""
        invalid_hunt = """---
hunt_id: INVALID
title: Test Hunt
status: completed
date: 2025-12-02
---

# Test Hunt

## LEARN: Prepare the Hunt
## OBSERVE: Expected Behaviors
## CHECK: Execute & Analyze
## KEEP: Findings & Response
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(invalid_hunt)
            temp_path = f.name

        try:
            parser = HuntParser(Path(temp_path))
            parser.parse()
            is_valid, errors = parser.validate()

            assert is_valid is False
            assert any("hunt_id" in err.lower() for err in errors)
        finally:
            os.unlink(temp_path)


class TestModuleFunctions:
    """Test suite for module-level convenience functions."""

    def test_parse_hunt_file(self):
        """Test parse_hunt_file convenience function."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name

        try:
            hunt_data = parse_hunt_file(Path(temp_path))

            assert hunt_data["hunt_id"] == "H-0001"
            assert hunt_data["frontmatter"]["title"] == "Test Hunt"
            assert "lock_sections" in hunt_data
        finally:
            os.unlink(temp_path)

    def test_validate_hunt_file(self, tmp_path):
        """Test validate_hunt_file convenience function."""
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(VALID_HUNT)

        is_valid, errors = validate_hunt_file(hunt_file)

        assert is_valid is True, errors
        assert len(errors) == 0

    def test_validate_invalid_hunt_file(self):
        """Test validate_hunt_file with invalid hunt."""
        incomplete_hunt = """---
hunt_id: H-0001
title: Test Hunt
---

# Test Hunt
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(incomplete_hunt)
            temp_path = f.name

        try:
            is_valid, errors = validate_hunt_file(Path(temp_path))

            assert is_valid is False
            assert len(errors) > 0
        finally:
            os.unlink(temp_path)

    def test_parse_nonexistent_file(self):
        """Test error handling for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            parse_hunt_file(Path("/nonexistent/path/hunt.md"))


class TestParseWithoutLockSections:
    """Test the fast-parse path that skips LOCK-section extraction."""

    def test_returns_frontmatter_and_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name
        try:
            parser = HuntParser(Path(temp_path))
            data = parser.parse_without_lock_sections()
            assert data["frontmatter"]["hunt_id"] == "H-0001"
            assert data["content"] != ""
            assert data["lock_sections"] == {}
        finally:
            os.unlink(temp_path)

    def test_fast_convenience_function(self):
        from athf.core.hunt_parser import parse_hunt_file_fast
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name
        try:
            data = parse_hunt_file_fast(Path(temp_path))
            assert data["hunt_id"] == "H-0001"
            assert data["lock_sections"] == {}
        finally:
            os.unlink(temp_path)

    def test_fast_parse_raises_for_missing_file(self):
        from athf.core.hunt_parser import parse_hunt_file_fast
        with pytest.raises(FileNotFoundError):
            parse_hunt_file_fast(Path("/nonexistent/hunt.md"))

    def test_content_is_searchable(self):
        """Fast parse must preserve body content so search_hunts() still works."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name
        try:
            from athf.core.hunt_parser import parse_hunt_file_fast
            data = parse_hunt_file_fast(Path(temp_path))
            assert "Hypothesis" in data["content"]
        finally:
            os.unlink(temp_path)


class TestTacticValidation:
    """Test tactic name validation in HuntParser.validate()."""

    def test_valid_tactics_pass(self, tmp_path):
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(VALID_HUNT)  # uses credential-access which is valid
        parser = HuntParser(hunt_file)
        parser.parse()
        is_valid, errors = parser.validate()
        assert not any("tactic" in e.lower() for e in errors)

    def test_invalid_tactic_reported(self, tmp_path):
        bad_tactic_hunt = """---
hunt_id: H-0001
title: Test Hunt
status: completed
date: 2025-12-02
tactics: [not-a-real-tactic]
techniques: [T1003.001]
platform: [Windows]
data_sources: [windows-event-logs]
---

## LEARN: Prepare the Hunt
Content.
## OBSERVE: Expected Behaviors
Content.
## CHECK: Execute & Analyze
Content.
## KEEP: Findings & Response
Content.
"""
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(bad_tactic_hunt)
        parser = HuntParser(hunt_file)
        parser.parse()
        is_valid, errors = parser.validate()
        assert not is_valid
        assert any("tactic" in e.lower() and "not-a-real-tactic" in e for e in errors)

    def test_non_string_tactics_skipped(self, tmp_path):
        """None or non-str entries in tactics list must not crash validation."""
        hunt_file = tmp_path / "H-0001.md"
        hunt_file.write_text(VALID_HUNT)
        parser = HuntParser(hunt_file)
        parser.parse()
        parser.frontmatter["tactics"] = [None, 42, "credential-access"]
        # Should not raise
        is_valid, errors = parser.validate()
        assert not any("tactic" in e.lower() for e in errors)


# Run tests with: pytest tests/test_hunt_parser.py -v

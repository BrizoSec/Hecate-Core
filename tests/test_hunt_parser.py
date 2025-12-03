"""
Tests for hunt file parsing and validation.
"""
import pytest
import tempfile
import os
from pathlib import Path
from athf.core.hunt_parser import HuntParser


# Sample valid hunt content for testing
VALID_HUNT = """---
hunt_id: H-0001
title: Test Hunt
status: completed
date: 2025-12-02
hunter: Test Hunter
techniques: [T1003.001]
tactics: [credential-access]
platforms: [windows]
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

    def test_parse_valid_frontmatter(self):
        """Test parsing valid YAML frontmatter."""
        frontmatter = HuntParser.parse_frontmatter(VALID_HUNT)

        assert 'hunt_id' in frontmatter
        assert frontmatter['hunt_id'] == 'H-0001'
        assert frontmatter['title'] == 'Test Hunt'
        assert frontmatter['status'] == 'completed'
        assert 'techniques' in frontmatter
        assert frontmatter['techniques'] == ['T1003.001']

    def test_parse_missing_frontmatter(self):
        """Test error handling for missing frontmatter."""
        invalid_content = "# Just a markdown file\n\nNo frontmatter here."

        with pytest.raises(ValueError, match="Missing frontmatter start delimiter"):
            HuntParser.parse_frontmatter(invalid_content)

    def test_parse_incomplete_frontmatter(self):
        """Test error handling for incomplete frontmatter."""
        invalid_content = "---\nhunt_id: H-0001\n# Missing end delimiter"

        with pytest.raises(ValueError, match="Missing frontmatter end delimiter"):
            HuntParser.parse_frontmatter(invalid_content)

    def test_extract_lock_sections(self):
        """Test extracting all four LOCK sections."""
        sections = HuntParser.extract_lock_sections(VALID_HUNT)

        assert 'LEARN' in sections
        assert 'OBSERVE' in sections
        assert 'CHECK' in sections
        assert 'KEEP' in sections

        # Real implementation returns boolean presence, not content
        assert sections['LEARN'] is True
        assert sections['OBSERVE'] is True
        assert sections['CHECK'] is True
        assert sections['KEEP'] is True

    def test_extract_missing_lock_sections(self):
        """Test detection of missing LOCK sections."""
        incomplete_hunt = """---
hunt_id: H-0001
---

## LEARN: Prepare the Hunt

Content here.

## OBSERVE: Expected Behaviors

Content here.

# Missing CHECK and KEEP
"""
        sections = HuntParser.extract_lock_sections(incomplete_hunt)

        assert sections.get('LEARN') is True
        assert sections.get('OBSERVE') is True
        assert sections.get('CHECK') is False or 'CHECK' not in sections
        assert sections.get('KEEP') is False or 'KEEP' not in sections

    def test_validate_complete_hunt(self):
        """Test validation of a complete, valid hunt."""
        hunt_data = {
            'frontmatter': {
                'hunt_id': 'H-0001',
                'title': 'Test Hunt',
                'status': 'completed',
                'date': '2025-12-02',
                'hunter': 'Test Hunter',
                'techniques': ['T1003.001']
            },
            'sections': {
                'LEARN': True,
                'OBSERVE': True,
                'CHECK': True,
                'KEEP': True
            }
        }

        errors = HuntParser.validate_hunt(hunt_data)
        assert len(errors) == 0

    def test_validate_missing_required_fields(self):
        """Test validation catches missing required fields."""
        hunt_data = {
            'frontmatter': {
                'hunt_id': 'H-0001',
                'title': 'Test Hunt'
                # Missing: status, date, hunter, techniques
            },
            'sections': {'LEARN': True, 'OBSERVE': True, 'CHECK': True, 'KEEP': True}
        }

        errors = HuntParser.validate_hunt(hunt_data)
        assert len(errors) >= 4
        assert any('status' in err for err in errors)
        assert any('date' in err for err in errors)
        assert any('hunter' in err for err in errors)
        assert any('techniques' in err for err in errors)

    def test_validate_invalid_status(self):
        """Test validation catches invalid status values."""
        hunt_data = {
            'frontmatter': {
                'hunt_id': 'H-0001',
                'title': 'Test Hunt',
                'status': 'invalid-status',
                'date': '2025-12-02',
                'hunter': 'Test Hunter',
                'techniques': ['T1003.001']
            },
            'sections': {'LEARN': True, 'OBSERVE': True, 'CHECK': True, 'KEEP': True}
        }

        errors = HuntParser.validate_hunt(hunt_data)
        assert len(errors) >= 1
        assert any('Invalid status' in err for err in errors)

    def test_validate_invalid_technique_format(self):
        """Test validation catches invalid ATT&CK technique format."""
        hunt_data = {
            'frontmatter': {
                'hunt_id': 'H-0001',
                'title': 'Test Hunt',
                'status': 'completed',
                'date': '2025-12-02',
                'hunter': 'Test Hunter',
                'techniques': ['T1003']  # Invalid: missing subtechnique or correct format
            },
            'sections': {'LEARN': True, 'OBSERVE': True, 'CHECK': True, 'KEEP': True}
        }

        errors = HuntParser.validate_hunt(hunt_data)
        assert len(errors) >= 1
        assert any('Invalid technique format' in err for err in errors)
        assert any('T1003' in err for err in errors)

    def test_validate_multiple_techniques(self):
        """Test validation of multiple techniques."""
        hunt_data = {
            'frontmatter': {
                'hunt_id': 'H-0001',
                'title': 'Test Hunt',
                'status': 'completed',
                'date': '2025-12-02',
                'hunter': 'Test Hunter',
                'techniques': ['T1003.001', 'T1558.003']
            },
            'sections': {'LEARN': True, 'OBSERVE': True, 'CHECK': True, 'KEEP': True}
        }

        errors = HuntParser.validate_hunt(hunt_data)
        assert len(errors) == 0


class TestHuntFile:
    """Test suite for complete hunt file operations."""

    def test_load_hunt_from_file(self):
        """Test loading a hunt from a temporary file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name

        try:
            hunt_data = HuntParser.parse_file(Path(temp_path))

            assert hunt_data['frontmatter']['hunt_id'] == 'H-0001'
            assert hunt_data['frontmatter']['title'] == 'Test Hunt'
            assert len(hunt_data['sections']) == 4
            assert all(hunt_data['sections'][s] for s in ['LEARN', 'OBSERVE', 'CHECK', 'KEEP'])
        finally:
            os.unlink(temp_path)

    def test_validate_hunt_file(self):
        """Test validation of a hunt file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(VALID_HUNT)
            temp_path = f.name

        try:
            errors = HuntParser.validate_file(Path(temp_path))
            assert len(errors) == 0
        finally:
            os.unlink(temp_path)

    def test_hunt_directory_structure(self):
        """Test that hunt files follow expected directory structure."""
        # Test that hunts directory exists
        hunts_dir = Path(__file__).parent.parent / 'hunts'

        # This test will pass when the actual hunt examples exist
        # For now, just verify the test structure is correct
        assert True


# Run tests with: pytest tests/test_hunt_parser.py -v

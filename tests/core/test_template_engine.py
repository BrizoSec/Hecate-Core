"""Tests for athf.core.template_engine - hunt template rendering."""

import pytest

from athf.core.template_engine import render_baseline_template, render_hunt_template


@pytest.mark.unit
class TestRenderHuntTemplate:
    """Test the render_hunt_template function."""

    def test_hypothesis_duration_included_when_provided(self):
        """hypothesis_duration_minutes appears in frontmatter when passed."""
        content = render_hunt_template(
            hunt_id="H-0099",
            title="Test Hunt",
            technique="T1003.001",
            hypothesis_duration_minutes=2.3,
        )

        assert "hypothesis_duration_minutes: 2.3" in content

    def test_hypothesis_duration_omitted_when_not_provided(self):
        """hypothesis_duration_minutes is absent from frontmatter when None."""
        content = render_hunt_template(
            hunt_id="H-0099",
            title="Test Hunt",
            technique="T1003.001",
        )

        assert "hypothesis_duration_minutes" not in content

    def test_hypothesis_duration_omitted_when_zero(self):
        """hypothesis_duration_minutes=0 is falsy, should be omitted."""
        content = render_hunt_template(
            hunt_id="H-0099",
            title="Test Hunt",
            technique="T1003.001",
            hypothesis_duration_minutes=0,
        )

        # Jinja2 treats 0 as falsy, so the field should not appear
        assert "hypothesis_duration_minutes" not in content

    def test_hypothesis_duration_with_spawned_from(self):
        """Both spawned_from and hypothesis_duration_minutes render correctly."""
        content = render_hunt_template(
            hunt_id="H-0099",
            title="Test Hunt",
            technique="T1003.001",
            spawned_from="R-0019",
            hypothesis_duration_minutes=0.8,
        )

        assert "spawned_from: R-0019" in content
        assert "hypothesis_duration_minutes: 0.8" in content

    def test_basic_template_renders(self):
        """Sanity check: basic template renders with required fields."""
        content = render_hunt_template(
            hunt_id="H-0001",
            title="Basic Hunt",
        )

        assert "hunt_id: H-0001" in content
        assert "title: Basic Hunt" in content
        assert "status: planning" in content

    def test_data_source_indexing_uses_real_first_source(self):
        """Regression test: the CHECK section's 'Index/Data Source' line used to
        index the pre-formatted YAML string ("[Splunk, CrowdStrike]") instead of
        the actual data_sources list, rendering a literal "[" instead of the
        first source name."""
        content = render_hunt_template(
            hunt_id="H-0001",
            title="Test Hunt",
            technique="T1003.001",
            data_sources=["Splunk", "CrowdStrike"],
        )

        assert "- **Index/Data Source:** Splunk" in content
        assert "- **Index/Data Source:** [" not in content


@pytest.mark.unit
class TestRenderBaselineTemplate:
    """Test the render_baseline_template function (PEAK Baseline/EDA hunt type)."""

    def test_basic_template_renders(self):
        """Sanity check: basic baseline template renders with required fields."""
        content = render_baseline_template(
            hunt_id="H-0001",
            title="Parent-Child Process Baseline",
            dimension="parent_process -> child_process pairs",
        )

        assert "hunt_id: H-0001" in content
        assert "title: Parent-Child Process Baseline" in content
        assert "hunt_type: baseline" in content
        assert "status: planning" in content
        assert "dimension: parent_process -> child_process pairs" in content

    def test_no_hypothesis_or_technique_fields(self):
        """Baseline hunts have no hypothesis and no ABLE/technique framing --
        the template shouldn't reference either."""
        content = render_baseline_template(hunt_id="H-0001", title="Test Baseline")

        assert "Hypothesis Statement" not in content
        assert "ABLE Scoping" not in content
        assert "techniques:" not in content

    def test_reuses_lock_top_level_headings(self):
        """Baseline hunts keep LEARN/OBSERVE/CHECK/KEEP so hunt_parser.py's
        section extraction works unmodified for both hunt types."""
        content = render_baseline_template(hunt_id="H-0001", title="Test Baseline")

        assert "## LEARN: Prepare the Baseline" in content
        assert "## OBSERVE: Expected Normal" in content
        assert "## CHECK: Characterize & Analyze" in content
        assert "## KEEP: Candidate Anomalies & Follow-up" in content

    def test_data_source_indexing_uses_real_first_source(self):
        """Same data_sources[0]-indexing regression as the hunt template."""
        content = render_baseline_template(
            hunt_id="H-0001",
            title="Test Baseline",
            data_sources=["EDR", "SIEM"],
        )

        assert "- **Index/Data Source:** EDR" in content
        assert "- **Index/Data Source:** [" not in content

    def test_objective_included_when_provided(self):
        """A provided objective appears verbatim rather than the placeholder."""
        content = render_baseline_template(
            hunt_id="H-0001",
            title="Test Baseline",
            objective="Establish normal PowerShell parent-child chains before hunting LOLBins.",
        )

        assert "Establish normal PowerShell parent-child chains before hunting LOLBins." in content

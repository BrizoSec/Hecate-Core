"""Versioned metadata projection for public review; never copy operator evidence."""

from typing import Any


def public_hunt_record(hunt_data: dict[str, Any]) -> dict[str, Any]:
    """Allowlist metadata instead of trying to redact arbitrary session content.

    Titles and tags still require the operator's privacy/rights review. This
    projection deliberately makes no claim of execution or detection success.
    """
    metadata = hunt_data.get("frontmatter", {})
    fields = ("hunt_id", "title", "status", "date", "platform", "tactics", "techniques", "data_sources", "tags")
    return {
        "schema_version": 1,
        "profile": "public_metadata",
        "release_state": "requires_review",
        "validation_scope": "not_provided",
        "metadata": {key: metadata[key] for key in fields if key in metadata},
    }

"""Parse hunt files (YAML frontmatter + markdown)."""

import re
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

# Compiled regex constants — compiled once at import time so HuntParser
# never recompiles them on every parse() call.
_RE_FM_EXTRACT = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_RE_FM_STRIP = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)

# LOCK section patterns.  KEEP uses a negative lookahead so "### Sub" doesn't
# fool the boundary match — see the in-line comment in _parse_lock_sections.
_RE_LOCK_LEARN = re.compile(r"##\s+LEARN[:\s].*?(?=##\s+OBSERVE|$)", re.DOTALL | re.IGNORECASE)
_RE_LOCK_OBSERVE = re.compile(r"##\s+OBSERVE[:\s].*?(?=##\s+CHECK|$)", re.DOTALL | re.IGNORECASE)
_RE_LOCK_CHECK = re.compile(r"##\s+CHECK[:\s].*?(?=##\s+KEEP|$)", re.DOTALL | re.IGNORECASE)
# KEEP is the last LOCK section — stop at the next top-level "## " heading only
# (not "### Sub"), so `(?!#)` ensures exactly two hashes, not three-or-more.
_RE_LOCK_KEEP = re.compile(r"##\s+KEEP[:\s].*?(?=\n##(?!#)\s+[A-Z]|\Z)", re.DOTALL | re.IGNORECASE)

_LOCK_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("learn", _RE_LOCK_LEARN),
    ("observe", _RE_LOCK_OBSERVE),
    ("check", _RE_LOCK_CHECK),
    ("keep", _RE_LOCK_KEEP),
]

_RE_HUNT_ID_FORMAT = re.compile(r"^[A-Z]+-\d+$")


class HuntParser:
    """Parser for ATHF hunt files."""

    def __init__(self, file_path: Path):
        """Initialize parser with hunt file path."""
        self.file_path = Path(file_path)
        self.frontmatter: Dict = {}
        self.content = ""
        self.lock_sections: Dict = {}

    def parse(self) -> Dict:
        """Parse hunt file and return structured data.

        Returns:
            Dict containing frontmatter, content, and LOCK sections
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Hunt file not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8") as f:
            raw = f.read()

        self.frontmatter = self._parse_frontmatter(raw)
        self.content = self._extract_content(raw)
        self.lock_sections = self._parse_lock_sections(self.content)

        return {
            "file_path": str(self.file_path),
            "hunt_id": self.frontmatter.get("hunt_id"),
            "frontmatter": self.frontmatter,
            "content": self.content,
            "lock_sections": self.lock_sections,
        }

    def parse_without_lock_sections(self) -> Dict:
        """Parse frontmatter and content only — skips the LOCK-section regexes.

        Useful for bulk operations (list, stats, search) that only need
        frontmatter fields and the raw markdown body.  lock_sections is
        returned as an empty dict so callers can detect the difference.

        Returns:
            Dict with frontmatter and content but empty lock_sections
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Hunt file not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8") as f:
            raw = f.read()

        self.frontmatter = self._parse_frontmatter(raw)
        self.content = self._extract_content(raw)
        self.lock_sections = {}

        return {
            "file_path": str(self.file_path),
            "hunt_id": self.frontmatter.get("hunt_id"),
            "frontmatter": self.frontmatter,
            "content": self.content,
            "lock_sections": self.lock_sections,
        }

    def _parse_frontmatter(self, content: str) -> Dict:
        """Extract and parse YAML frontmatter."""
        match = _RE_FM_EXTRACT.match(content)
        if not match:
            return {}
        try:
            return yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML frontmatter: {e}")

    def _extract_content(self, content: str) -> str:
        """Extract content after frontmatter."""
        return _RE_FM_STRIP.sub("", content, count=1).strip()

    def _parse_lock_sections(self, content: str) -> Dict[str, str]:
        """Parse LOCK pattern sections from content.

        Returns:
            Dict with keys: learn, observe, check, keep
        """
        sections = {}
        for section_name, pattern in _LOCK_PATTERNS:
            match = pattern.search(content)
            if match:
                sections[section_name] = match.group(0).strip()
        return sections

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate hunt structure.

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        # Check frontmatter exists
        if not self.frontmatter:
            errors.append("Missing YAML frontmatter")

        # Check required frontmatter fields
        required_fields = ["hunt_id", "title", "status", "date"]
        for field in required_fields:
            if field not in self.frontmatter:
                errors.append(f"Missing required frontmatter field: {field}")

        # Validate hunt_id format (e.g., H-0001)
        hunt_id = self.frontmatter.get("hunt_id", "")
        if hunt_id and not _RE_HUNT_ID_FORMAT.match(hunt_id):
            errors.append(f"Invalid hunt_id format: {hunt_id} (expected format: H-0001)")

        # hunt_id must match the filename so files can't silently diverge
        # after being copied or renamed (e.g., H-0001.md with hunt_id: H-0042).
        filename_stem = self.file_path.stem
        if hunt_id and filename_stem and hunt_id != filename_stem:
            errors.append(
                f"hunt_id '{hunt_id}' does not match filename '{filename_stem}.md'"
            )

        # Validate technique IDs against the ATT&CK matrix when STIX data is
        # available. Skipped when using the fallback provider (no per-technique
        # data) to avoid false positives for users who haven't run 'athf attack update'.
        from athf.core.attack_matrix import get_sorted_tactics, get_technique, is_using_stix
        if is_using_stix():
            for technique in self.frontmatter.get("techniques", []):
                if isinstance(technique, str) and technique:
                    if get_technique(technique) is None:
                        errors.append(
                            f"Unknown MITRE technique: {technique} (not found in ATT&CK matrix — typo?)"
                        )

        # Validate tactic names against the ATT&CK matrix.
        # get_sorted_tactics() works with both STIX and the fallback provider,
        # so this check runs unconditionally.
        valid_tactics = set(get_sorted_tactics())
        for tactic in self.frontmatter.get("tactics", []):
            if isinstance(tactic, str) and tactic and tactic not in valid_tactics:
                errors.append(
                    f"Unknown MITRE tactic: '{tactic}' — did you mean one of: "
                    + ", ".join(sorted(valid_tactics)[:5]) + ", ..."
                )

        # Check LOCK sections present
        lock_sections = ["learn", "observe", "check", "keep"]
        for section in lock_sections:
            if section not in self.lock_sections:
                errors.append(f"Missing LOCK section: {section.upper()}")

        return (len(errors) == 0, errors)


def parse_hunt_file(file_path: Path) -> Dict:
    """Convenience function to parse a hunt file (includes LOCK sections).

    Args:
        file_path: Path to hunt file

    Returns:
        Parsed hunt data
    """
    parser = HuntParser(file_path)
    return parser.parse()


def parse_hunt_file_fast(file_path: Path) -> Dict:
    """Convenience function to parse a hunt file without LOCK-section extraction.

    Faster than parse_hunt_file() for bulk operations that only need frontmatter
    and the raw content body (e.g., list, stats, search).

    Args:
        file_path: Path to hunt file

    Returns:
        Parsed hunt data with empty lock_sections dict
    """
    parser = HuntParser(file_path)
    return parser.parse_without_lock_sections()


def validate_hunt_file(file_path: Path) -> Tuple[bool, List[str]]:
    """Convenience function to validate a hunt file.

    Args:
        file_path: Path to hunt file

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    parser = HuntParser(file_path)
    parser.parse()
    return parser.validate()

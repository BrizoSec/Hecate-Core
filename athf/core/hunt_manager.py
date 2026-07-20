"""Manage hunt files and operations."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from athf.core.attack_matrix import get_sorted_tactics, get_tactic_technique_count, get_technique, get_total_techniques
from athf.core.hunt_parser import parse_hunt_file
from athf.utils.validation import validate_file_path, validate_hunt_id

# Documentation files to exclude when discovering hunt files at any directory level
EXCLUDED_DOC_FILES = {"README.md", "FORMAT_GUIDELINES.md", "INDEX.md", "AGENTS.md", "WEEKLY_SUMMARY_TEMPLATE.md"}


class HuntManager:
    """Manage hunt files and operations."""

    # Class-level (shared across instances), keyed by resolved hunts_dir.
    # Every call site constructs a *fresh* HuntManager (grep confirms no
    # caller reuses one across calls -- both CLI commands and MCP tools
    # instantiate a new one per invocation/tool-call), so a per-instance
    # cache would help nothing: list_hunts()/calculate_stats()/
    # calculate_attack_coverage() each re-read and re-parse every hunt
    # file's frontmatter *and* full LOCK-section markdown from disk, every
    # single call, with no memoization -- O(n) full-file I/O and YAML/regex
    # parsing that scales linearly with hunt count and is paid repeatedly
    # within a single long-lived process (the MCP server calls one of these
    # per tool invocation, often several times per session against the same
    # unchanged directory).
    #
    # Keyed on a cheap fingerprint (file count + max mtime) rather than
    # time-based expiry so it can never serve stale data for longer than an
    # `os.stat()` scan takes to notice a change -- any hunt created, edited,
    # or removed invalidates it on the very next call, automatically.
    _parse_cache: Dict[Path, Tuple[Tuple[int, float], List[Tuple[Path, Dict]]]] = {}

    def __init__(self, hunts_dir: Optional[Path] = None):
        """Initialize hunt manager.

        Args:
            hunts_dir: Directory containing hunt files (default: ./hunts)
        """
        self.hunts_dir = Path(hunts_dir) if hunts_dir else Path.cwd() / "hunts"

        if not self.hunts_dir.exists():
            self.hunts_dir.mkdir(parents=True, exist_ok=True)

    def find_hunt_file(self, hunt_id: str) -> Optional[Path]:
        """Find a hunt file by ID, searching recursively.

        Args:
            hunt_id: Hunt ID (e.g., H-0001)

        Returns:
            Path to the hunt file, or None if not found
        """
        if not validate_hunt_id(hunt_id):
            return None
        # Try flat first for speed
        flat = self.hunts_dir / f"{hunt_id}.md"
        if flat.exists():
            return flat
        # Recursive fallback
        matches = list(self.hunts_dir.rglob(f"{hunt_id}.md"))
        if not matches:
            return None
        result = matches[0]
        if not validate_file_path(result, self.hunts_dir):
            return None
        return result

    def find_all_hunt_files(self) -> List[Path]:
        """Find all hunt files recursively, excluding documentation.

        Returns:
            Sorted list of hunt file Paths
        """
        return sorted(f for f in self.hunts_dir.rglob("*.md") if f.name not in EXCLUDED_DOC_FILES)

    def _cached_parsed_hunt_data(self) -> List[Tuple[Path, Dict]]:
        """Return (file_path, parsed_data) for every hunt file, reusing the
        class-level cache when nothing in the directory has changed since
        the last call (see the cache field's docstring for why this is
        class-level, not per-instance).

        A parse failure for an individual file is swallowed here (matching
        list_hunts()'s prior per-file try/except) so one malformed hunt file
        doesn't take down the whole cache entry.
        """
        hunt_files = self.find_all_hunt_files()
        fingerprint = (
            len(hunt_files),
            max((f.stat().st_mtime for f in hunt_files), default=0.0),
        )

        cache_key = self.hunts_dir.resolve()
        cached = HuntManager._parse_cache.get(cache_key)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]

        parsed: List[Tuple[Path, Dict]] = []
        for hunt_file in hunt_files:
            try:
                parsed.append((hunt_file, parse_hunt_file(hunt_file)))
            except Exception:
                continue

        HuntManager._parse_cache[cache_key] = (fingerprint, parsed)
        return parsed

    def list_hunts(
        self,
        status: Optional[str] = None,
        tactic: Optional[str] = None,
        technique: Optional[str] = None,
        platform: Optional[str] = None,
        directory: Optional[str] = None,
        hunt_type: Optional[str] = None,
    ) -> List[Dict]:
        """List all hunts with optional filters.

        Args:
            status: Filter by status (planning, active, completed, etc.)
            tactic: Filter by MITRE tactic
            technique: Filter by MITRE technique (e.g., T1003.001)
            platform: Filter by platform (Windows, Linux, macOS, Cloud)
            directory: Filter by environment directory (test or production)
            hunt_type: Filter by hunt type (hypothesis-driven, baseline). Hunts
                without an explicit `hunt_type` frontmatter field are treated
                as "hypothesis-driven" -- every hunt created before baseline
                hunts existed is one, so this keeps them all filterable/countable
                without needing to backfill the field onto old hunt files.

        Returns:
            List of hunt metadata dicts
        """
        hunts = []

        for hunt_file, hunt_data in self._cached_parsed_hunt_data():
            try:
                frontmatter = hunt_data.get("frontmatter", {})
                hunt_type_val = frontmatter.get("hunt_type") or "hypothesis-driven"

                # Determine environment from file path
                hunt_file_parts = hunt_file.parts
                environment = None
                if "test" in hunt_file_parts:
                    environment = "test"
                elif "production" in hunt_file_parts:
                    environment = "production"

                # Apply filters
                if status and frontmatter.get("status") != status:
                    continue

                if tactic and tactic not in frontmatter.get("tactics", []):
                    continue

                if technique and technique not in frontmatter.get("techniques", []):
                    continue

                if platform and platform not in frontmatter.get("platform", []):
                    continue

                if directory and environment != directory:
                    continue

                if hunt_type and hunt_type_val != hunt_type:
                    continue

                # Extract summary info
                date_val = frontmatter.get("date")
                # Convert date objects to strings for JSON serialization
                if hasattr(date_val, "isoformat"):
                    date_str = date_val.isoformat()
                else:
                    date_str = str(date_val) if date_val else None

                hunts.append(
                    {
                        "hunt_id": frontmatter.get("hunt_id"),
                        "title": frontmatter.get("title"),
                        "status": frontmatter.get("status"),
                        "date": date_str,
                        "platform": frontmatter.get("platform", []),
                        "tactics": frontmatter.get("tactics", []),
                        "techniques": frontmatter.get("techniques", []),
                        "findings_count": frontmatter.get("findings_count", 0),
                        "true_positives": frontmatter.get("true_positives", 0),
                        "false_positives": frontmatter.get("false_positives", 0),
                        "file_path": str(hunt_file),
                        "environment": environment,
                        "hunt_type": hunt_type_val,
                    }
                )

            except Exception:
                # Skip files that can't be parsed
                continue

        return hunts

    def get_hunt(self, hunt_id: str) -> Optional[Dict]:
        """Get a specific hunt by ID.

        Args:
            hunt_id: Hunt ID (e.g., H-0001)

        Returns:
            Hunt data dict or None if not found
        """
        hunt_file = self.find_hunt_file(hunt_id)
        if not hunt_file:
            return None

        return parse_hunt_file(hunt_file)

    def get_next_hunt_id(self, prefix: str = "H-") -> str:
        """Calculate the next available hunt ID.

        Args:
            prefix: Hunt ID prefix (default: H-)

        Returns:
            Next hunt ID (e.g., H-0023)
        """
        hunts = self.list_hunts()

        if not hunts:
            return f"{prefix}0001"

        # Extract numbers from hunt IDs with matching prefix
        numbers = []
        pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")

        for hunt in hunts:
            hunt_id = hunt.get("hunt_id")
            if not hunt_id or not isinstance(hunt_id, str):
                continue
            match = pattern.match(hunt_id)
            if match:
                numbers.append(int(match.group(1)))

        if not numbers:
            return f"{prefix}0001"

        # Next number with zero-padding
        next_num = max(numbers) + 1
        return f"{prefix}{next_num:04d}"

    def search_hunts(self, query: str, directory: Optional[str] = None) -> List[Dict]:
        """Full-text search across all hunt files.

        Args:
            query: Search query string
            directory: Filter by environment directory (test or production)

        Returns:
            List of matching hunts
        """
        results = []
        query_lower = query.lower()

        for hunt_file in self.find_all_hunt_files():
            # Determine environment from file path
            hunt_file_parts = hunt_file.parts
            environment = None
            if "test" in hunt_file_parts:
                environment = "test"
            elif "production" in hunt_file_parts:
                environment = "production"

            # Apply directory filter
            if directory and environment != directory:
                continue

            try:
                with open(hunt_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Check if query appears in file
                if query_lower in content.lower():
                    hunt_data = parse_hunt_file(hunt_file)
                    frontmatter = hunt_data.get("frontmatter", {})

                    results.append(
                        {
                            "hunt_id": frontmatter.get("hunt_id"),
                            "title": frontmatter.get("title"),
                            "status": frontmatter.get("status"),
                            "file_path": str(hunt_file),
                            "environment": environment,
                        }
                    )

            except Exception:
                continue

        return results

    def calculate_stats(self) -> Dict:
        """Calculate hunt program statistics.

        Baseline hunts (hunt_type: baseline) are counted in total_hunts and
        completed_hunts -- they're real hunting activity -- but excluded from
        the success_rate denominator: a baseline hunt has no hypothesis to
        confirm, so true_positives is always 0 by construction, and including
        them would silently drag down the org's success rate for hunts that
        were never trying to produce a true positive in the first place.

        Returns:
            Dict with success rates, TP/FP ratios, coverage metrics
        """
        hunts = self.list_hunts()

        if not hunts:
            return {
                "total_hunts": 0,
                "completed_hunts": 0,
                "baseline_hunts": 0,
                "total_findings": 0,
                "true_positives": 0,
                "false_positives": 0,
                "success_rate": 0.0,
                "tp_fp_ratio": 0.0,
            }

        total_hunts = len(hunts)
        completed_hunts = len([h for h in hunts if h.get("status") == "completed"])
        baseline_hunts = len([h for h in hunts if h.get("hunt_type") == "baseline"])

        total_findings = sum(h.get("findings_count", 0) for h in hunts)
        total_tp = sum(h.get("true_positives", 0) for h in hunts)
        total_fp = sum(h.get("false_positives", 0) for h in hunts)

        # Success rate is scoped to hypothesis-driven hunts only (see docstring).
        hypothesis_driven_completed = [h for h in hunts if h.get("status") == "completed" and h.get("hunt_type") != "baseline"]
        hunts_with_tp = len([h for h in hypothesis_driven_completed if h.get("true_positives", 0) > 0])
        success_rate = (hunts_with_tp / len(hypothesis_driven_completed) * 100) if hypothesis_driven_completed else 0.0

        # Calculate TP/FP ratio
        tp_fp_ratio = (total_tp / total_fp) if total_fp > 0 else float("inf")

        return {
            "total_hunts": total_hunts,
            "completed_hunts": completed_hunts,
            "baseline_hunts": baseline_hunts,
            "total_findings": total_findings,
            "true_positives": total_tp,
            "false_positives": total_fp,
            "success_rate": round(success_rate, 1),
            "tp_fp_ratio": round(tp_fp_ratio, 2) if tp_fp_ratio != float("inf") else "∞",
        }

    def calculate_attack_coverage(self) -> Dict[str, Any]:
        """Calculate MITRE ATT&CK technique coverage with hunt references.

        Returns:
            Dict with structure:
            {
                "summary": {
                    "total_hunts": int,
                    "completed_hunts": int,
                    "unique_techniques": int,
                    "tactics_covered": int,
                    "total_techniques": int,
                    "overall_coverage_pct": float
                },
                "by_tactic": {
                    "tactic-name": {
                        "hunt_count": int,
                        "hunt_ids": List[str],
                        "techniques": {
                            "T1234.001": ["H-0001", "H-0003"]
                        },
                        "techniques_covered": int,
                        "total_techniques": int,
                        "coverage_pct": float
                    }
                }
            }
        """
        hunts = self.list_hunts()

        # Initialize coverage structure for ALL ATT&CK tactics (not just ones with hunts)
        coverage_by_tactic: Dict[str, Dict[str, Any]] = {}
        for tactic_key in get_sorted_tactics():
            coverage_by_tactic[tactic_key] = {
                "hunt_count": 0,
                "hunt_ids": set(),
                "techniques": {},
                "total_techniques": get_tactic_technique_count(tactic_key),
            }

        all_unique_techniques: Set[str] = set()

        for hunt in hunts:
            hunt_id = hunt.get("hunt_id", "UNKNOWN")
            tactics = hunt.get("tactics", [])
            techniques = hunt.get("techniques", [])

            # Track all unique techniques across all hunts
            all_unique_techniques.update(techniques)

            for tactic in tactics:
                # Skip if tactic not in ATT&CK matrix (might be custom tactic)
                if tactic not in coverage_by_tactic:
                    continue

                # Track hunt IDs for this tactic (the hunter's own declared
                # scope for this hunt -- kept as-is even where a technique
                # below turns out to be mistagged, since the hunt itself may
                # still be legitimately about this tactic).
                coverage_by_tactic[tactic]["hunt_ids"].add(hunt_id)

                # Track which hunts cover each technique under this tactic --
                # only when the technique actually belongs to this tactic per
                # ATT&CK. Previously every technique on a hunt was credited to
                # every tactic listed on that same hunt with no check, so e.g.
                # tactics: [credential-access], techniques: [T1053.005, T1204]
                # (Scheduled Task/Persistence and User Execution/Execution --
                # neither is a credential-access technique) inflated
                # credential-access coverage while crediting nothing to the
                # tactics those techniques actually belong to.
                for technique in techniques:
                    info = get_technique(technique)
                    technique_tactics = info.get("tactic_shortnames") if info else None
                    # None means "couldn't verify" (unknown technique ID, or
                    # the hardcoded fallback ATT&CK provider with no
                    # per-technique tactic data) -- fall back to trusting the
                    # hunt's own declared tactic rather than dropping the
                    # data point entirely. An empty/non-empty list means we
                    # *can* verify, so only credit a real match.
                    if technique_tactics is not None and tactic not in technique_tactics:
                        continue
                    if technique not in coverage_by_tactic[tactic]["techniques"]:
                        coverage_by_tactic[tactic]["techniques"][technique] = []
                    coverage_by_tactic[tactic]["techniques"][technique].append(hunt_id)

        # Calculate coverage percentages and convert sets to sorted lists
        for tactic in coverage_by_tactic:
            coverage_by_tactic[tactic]["hunt_count"] = len(coverage_by_tactic[tactic]["hunt_ids"])
            coverage_by_tactic[tactic]["hunt_ids"] = sorted(coverage_by_tactic[tactic]["hunt_ids"])
            coverage_by_tactic[tactic]["techniques_covered"] = len(coverage_by_tactic[tactic]["techniques"])

            # Calculate coverage percentage
            total = coverage_by_tactic[tactic]["total_techniques"]
            covered = coverage_by_tactic[tactic]["techniques_covered"]
            coverage_by_tactic[tactic]["coverage_pct"] = (covered / total * 100) if total > 0 else 0.0

        # Calculate overall coverage
        tactics_with_hunts = len([t for t in coverage_by_tactic.values() if t["hunt_count"] > 0])
        total_techniques = get_total_techniques()
        overall_coverage_pct = (len(all_unique_techniques) / total_techniques * 100) if total_techniques > 0 else 0.0

        # Build summary
        summary = {
            "total_hunts": len(hunts),
            "completed_hunts": len([h for h in hunts if h.get("status") == "completed"]),
            "unique_techniques": len(all_unique_techniques),
            "tactics_covered": tactics_with_hunts,
            "total_techniques": total_techniques,
            "overall_coverage_pct": overall_coverage_pct,
        }

        return {"summary": summary, "by_tactic": coverage_by_tactic}

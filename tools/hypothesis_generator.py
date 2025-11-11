#!/usr/bin/env python3
"""
simple_hunt_server.py
Simplified hypothesis generation tool for Claude Code (no MCP SDK required)
"""

import sys
import json
from pathlib import Path
import re


# Configuration - assumes running from repo root
REPO_ROOT = Path(__file__).parent.parent
HUNTS_DIR = REPO_ROOT / "hunts"
AGENTS_FILE = REPO_ROOT / "AGENTS.md"


def generate_hypothesis(threat_context: str, technique_id: str):
    """Generate hunt hypothesis with context from past hunts."""

    # Search past hunts
    past_hunts = search_past_hunts(technique_id)

    # Load data sources
    data_sources = load_data_sources()

    # Extract lessons
    lessons = extract_lessons(past_hunts)

    # Build context
    context = {
        "threat": threat_context,
        "technique": technique_id,
        "past_hunts_found": len(past_hunts),
        "past_hunts": past_hunts[:3],  # Limit to 3 most relevant
        "available_data_sources": data_sources,
        "lessons_learned": lessons,
        "next_hunt_id": get_next_hunt_id()
    }

    return context


def search_past_hunts(technique_id: str):
    """Search for past hunts related to this technique."""
    if not HUNTS_DIR.exists():
        return []

    related = []
    for hunt_file in HUNTS_DIR.glob("H-*.md"):
        try:
            content = hunt_file.read_text()
            if technique_id.upper() in content.upper():
                related.append({
                    "file": hunt_file.name,
                    "technique": technique_id,
                    "keep_section": extract_keep_section(content),
                    "title": extract_title(content)
                })
        except Exception:
            continue

    return related


def load_data_sources():
    """Load available data sources from AGENTS.md."""
    if not AGENTS_FILE.exists():
        return []

    try:
        content = AGENTS_FILE.read_text()
        lines = content.split('\n')
        in_table = False
        sources = []

        for line in lines:
            if '## Data Sources' in line:
                in_table = True
                continue
            if in_table and line.startswith('|') and 'Source' not in line and '---' not in line:
                parts = [p.strip() for p in line.split('|')[1:-1]]
                if len(parts) >= 4:
                    sources.append({
                        "source": parts[0],
                        "description": parts[1],
                        "platform": parts[2],
                        "notes": parts[3]
                    })
            elif in_table and line.startswith('##'):
                break

        return sources
    except Exception:
        return []


def extract_lessons(past_hunts):
    """Extract lessons learned from past hunts."""
    lessons = []
    for hunt in past_hunts:
        keep = hunt.get("keep_section", "")
        if keep:
            lessons.append({
                "hunt": hunt["file"],
                "lessons": keep
            })
    return lessons


def extract_keep_section(content: str):
    """Extract the Keep section from a hunt file."""
    match = re.search(r'\*\*Keep\*\*\s*\n(.*?)(?=\n\*\*|\n#|$)', content, re.DOTALL)
    if match:
        return match.group(1).strip()[:200]  # Limit length
    return ""


def extract_title(content: str):
    """Extract the title from a hunt file."""
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return "Unknown"


def get_next_hunt_id():
    """Get the next available hunt ID."""
    if not HUNTS_DIR.exists():
        return "H-0001"

    max_id = 0
    for hunt_file in HUNTS_DIR.glob("H-*.md"):
        match = re.search(r'H-(\d+)', hunt_file.name)
        if match:
            hunt_id = int(match.group(1))
            max_id = max(max_id, hunt_id)

    return f"H-{max_id + 1:04d}"


def main():
    """CLI interface for testing."""
    if len(sys.argv) < 3:
        print("Usage: python3 simple_hunt_server.py <technique_id> <threat_context>")
        print("Example: python3 simple_hunt_server.py T1059.003 'New Qakbot campaign using PowerShell'")
        sys.exit(1)

    technique_id = sys.argv[1]
    threat_context = ' '.join(sys.argv[2:])

    context = generate_hypothesis(threat_context, technique_id)

    print(json.dumps(context, indent=2))
    print("\n" + "="*80)
    print("INSTRUCTIONS FOR CLAUDE:")
    print("="*80)
    print("""
Generate a complete LOCK-formatted hunt hypothesis using this context:

1. Reference past hunts to avoid duplication
2. Incorporate lessons learned from similar hunts
3. Use only the available data sources listed
4. Follow the LOCK pattern: Learn → Observe → Check → Keep
5. Include the next hunt ID in the title
6. Make queries practical and executable

Format the output as a complete markdown hunt file ready to save.
""")


if __name__ == "__main__":
    main()

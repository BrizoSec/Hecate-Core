"""
hunt_mcp_server.py
Level 3 MCP server - provides hypothesis generation tool for Claude Code
"""

from mcp.server.fastmcp import FastMCP
from pathlib import Path
import json
import re

# Initialize FastMCP server
mcp = FastMCP("athf-hunt-server")

# Configuration - automatic relative paths from repo root
REPO_ROOT = Path(__file__).parent.parent.parent
HUNTS_DIR = REPO_ROOT / "hunts"
AGENTS_FILE = REPO_ROOT / "AGENTS.md"


@mcp.tool()
def generate_hunt_hypothesis(threat_context: str, technique_id: str) -> str:
    """
    Generate a LOCK-formatted hunt hypothesis from CTI or threat context.

    Args:
        threat_context: CTI report, alert details, or threat description
        technique_id: MITRE ATT&CK technique ID (e.g., T1059.001)

    Returns:
        Structured context and instructions for generating a hunt hypothesis
    """
    # Search past hunts for this technique
    past_hunts = search_past_hunts(technique_id)

    # Load available data sources from AGENTS.md
    data_sources = load_data_sources()

    # Extract lessons learned from past hunts
    lessons = extract_lessons(past_hunts)

    # Build structured context for Claude
    context = {
        "threat": threat_context,
        "technique": technique_id,
        "past_hunts_found": len(past_hunts),
        "past_hunts": past_hunts,
        "available_data_sources": data_sources,
        "lessons_learned": lessons,
        "next_hunt_id": get_next_hunt_id()
    }

    # Return formatted context with instructions
    return f"""CONTEXT:
{json.dumps(context, indent=2)}

INSTRUCTIONS:
Generate a complete LOCK-formatted hunt hypothesis using this context:

1. Reference past hunts to avoid duplication
2. Incorporate lessons learned from similar hunts
3. Use only the available data sources listed
4. Follow the LOCK pattern: Learn → Observe → Check → Keep
5. Include the next hunt ID in the title
6. Make queries practical and executable

Format the output as a complete markdown hunt file ready to save.
"""


def search_past_hunts(technique_id: str):
    """Search for past hunts related to this technique."""
    if not HUNTS_DIR.exists():
        return []

    related = []
    for hunt_file in HUNTS_DIR.glob("H-*.md"):
        try:
            content = hunt_file.read_text()
            # Look for technique ID in the content
            if technique_id.upper() in content.upper():
                related.append({
                    "file": hunt_file.name,
                    "technique": technique_id,
                    "keep_section": extract_keep_section(content),
                    "title": extract_title(content)
                })
        except Exception as e:
            # Skip files that can't be read
            continue

    return related


def load_data_sources():
    """Load available data sources from AGENTS.md."""
    if not AGENTS_FILE.exists():
        return []

    try:
        content = AGENTS_FILE.read_text()

        # Find the Data Sources table
        lines = content.split('\n')
        in_table = False
        sources = []

        for line in lines:
            if '## Data Sources' in line:
                in_table = True
                continue
            if in_table and line.startswith('|') and 'Source' not in line and '---' not in line:
                # Parse table row
                parts = [p.strip() for p in line.split('|')[1:-1]]
                if len(parts) >= 4:
                    sources.append({
                        "source": parts[0],
                        "description": parts[1],
                        "platform": parts[2],
                        "notes": parts[3]
                    })
            elif in_table and line.startswith('##'):
                # End of table
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
            # Extract key lessons from the Keep section
            lessons.append({
                "hunt": hunt["file"],
                "lessons": keep
            })
    return lessons


def extract_keep_section(content: str):
    """Extract the Keep section from a hunt file."""
    match = re.search(r'\*\*Keep\*\*\s*\n(.*?)(?=\n\*\*|\n#|$)', content, re.DOTALL)
    if match:
        return match.group(1).strip()
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

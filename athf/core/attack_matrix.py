"""MITRE ATT&CK Matrix reference data.

This module contains reference data for the MITRE ATT&CK Enterprise matrix,
including tactic ordering and technique counts.
"""

from typing import Dict, List, TypedDict


class TacticInfo(TypedDict):
    """Type definition for tactic information."""

    name: str
    technique_count: int
    order: int


# MITRE ATT&CK Enterprise Matrix v14 (January 2024)
# Approximate technique counts per tactic (includes sub-techniques)
ATTACK_TACTICS: Dict[str, TacticInfo] = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "technique_count": 10,
        "order": 1,
    },
    "resource-development": {
        "name": "Resource Development",
        "technique_count": 7,
        "order": 2,
    },
    "initial-access": {
        "name": "Initial Access",
        "technique_count": 9,
        "order": 3,
    },
    "execution": {
        "name": "Execution",
        "technique_count": 12,
        "order": 4,
    },
    "persistence": {
        "name": "Persistence",
        "technique_count": 19,
        "order": 5,
    },
    "privilege-escalation": {
        "name": "Privilege Escalation",
        "technique_count": 13,
        "order": 6,
    },
    "defense-evasion": {
        "name": "Defense Evasion",
        "technique_count": 42,
        "order": 7,
    },
    "credential-access": {
        "name": "Credential Access",
        "technique_count": 15,
        "order": 8,
    },
    "discovery": {
        "name": "Discovery",
        "technique_count": 30,
        "order": 9,
    },
    "lateral-movement": {
        "name": "Lateral Movement",
        "technique_count": 9,
        "order": 10,
    },
    "collection": {
        "name": "Collection",
        "technique_count": 17,
        "order": 11,
    },
    "command-and-control": {
        "name": "Command and Control",
        "technique_count": 16,
        "order": 12,
    },
    "exfiltration": {
        "name": "Exfiltration",
        "technique_count": 9,
        "order": 13,
    },
    "impact": {
        "name": "Impact",
        "technique_count": 13,
        "order": 14,
    },
}

# Total techniques across all tactics
TOTAL_TECHNIQUES = sum(tactic["technique_count"] for tactic in ATTACK_TACTICS.values())


def get_tactic_display_name(tactic_key: str) -> str:
    """Get the display name for a tactic key.

    Args:
        tactic_key: Tactic key (e.g., "credential-access")

    Returns:
        Display name (e.g., "Credential Access")
    """
    if tactic_key in ATTACK_TACTICS:
        return ATTACK_TACTICS[tactic_key]["name"]
    return tactic_key.replace("-", " ").title()


def get_tactic_technique_count(tactic_key: str) -> int:
    """Get the total technique count for a tactic.

    Args:
        tactic_key: Tactic key (e.g., "credential-access")

    Returns:
        Total technique count for the tactic
    """
    if tactic_key in ATTACK_TACTICS:
        return ATTACK_TACTICS[tactic_key]["technique_count"]
    return 0


def get_sorted_tactics() -> List[str]:
    """Get all tactic keys sorted by ATT&CK matrix order.

    Returns:
        List of tactic keys in matrix order
    """
    return sorted(ATTACK_TACTICS.keys(), key=lambda k: ATTACK_TACTICS[k]["order"])

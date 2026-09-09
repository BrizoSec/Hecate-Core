#!/usr/bin/env python3
"""Example: Using Splunk API integration with Hecate.

This script demonstrates how to programmatically execute Splunk queries
for threat hunting workflows.

Setup:
    export SPLUNK_HOST="splunk.example.com"
    export SPLUNK_TOKEN="your-token-here"

Usage:
    python splunk_example.py
"""

from typing import Any, Callable, List, Optional

from hecate_agent.core.splunk_client import create_client_from_env


def _connect() -> Optional[Any]:
    """Create a client from the environment, or explain what is missing."""
    try:
        return create_client_from_env()
    except ValueError as e:
        print(f"❌ Error: {e}")
        print("\nPlease set SPLUNK_HOST and SPLUNK_TOKEN environment variables:")
        print("  export SPLUNK_HOST='splunk.example.com'")
        print("  export SPLUNK_TOKEN='your-token-here'")
        return None


def _show_connection(client: Any) -> bool:
    """Print the server version. False means the connection is unusable."""
    print("Testing connection...")
    try:
        info = client.test_connection()
        if "entry" in info and info["entry"]:
            content = info["entry"][0].get("content", {})
            print(f"✅ Connected to Splunk {content.get('version', 'N/A')}\n")
        return True
    except Exception as e:
        print(f"❌ Connection failed: {e}\n")
        return False


def _show_indexes(client: Any) -> None:
    """List the first few indexes available to this token."""
    print("Available indexes:")
    try:
        indexes = client.get_indexes()
        for idx in sorted(indexes)[:10]:
            print(f"  • {idx}")
        if len(indexes) > 10:
            print(f"  ... and {len(indexes) - 10} more")
        print()
    except Exception as e:
        print(f"❌ Error listing indexes: {e}\n")


def _format_auth_failures(results: List[dict]) -> None:
    print(f"⚠️  Found {len(results)} suspicious patterns:\n")
    for i, event in enumerate(results[:5], 1):
        print(
            f"{i}. IP: {event.get('src_ip', 'N/A')}, "
            f"Account: {event.get('Account_Name', 'N/A')}, "
            f"Failures: {event.get('count', 0)}"
        )


def _format_sourcetype_counts(results: List[dict]) -> None:
    for i, event in enumerate(results, 1):
        print(f"{i}. {event.get('sourcetype', 'N/A')}: {event.get('count', 0):,} events")


#: (heading, SPL, run asynchronously, result formatter, empty-result message).
#: A table rather than three copied blocks -- the examples differ only in these
#: five things, and adding a fourth should not mean copying the scaffolding.
EXAMPLES = (
    (
        "🎯 Hunt Example 1: Windows Authentication Failures",
        """
    index=thrunt sourcetype="XmlWinEventLog" EventCode=4625
    | stats count by Account_Name, src_ip
    | where count > 5
    | sort -count
    """,
        False,
        _format_auth_failures,
        "✅ No suspicious activity detected",
    ),
    (
        "🎯 Hunt Example 2: Data Source Inventory (thrunt index)",
        """
    index=thrunt
    | stats count by sourcetype
    | sort -count
    """,
        False,
        _format_sourcetype_counts,
        "No data found",
    ),
    (
        "🎯 Hunt Example 3: Network Traffic Analysis (Async)",
        """
    index=thrunt sourcetype="stream:*"
    | stats count by sourcetype
    | sort -count
    """,
        True,
        _format_sourcetype_counts,
        "No data found",
    ),
)


def _run_example(
    client: Any,
    heading: str,
    query: str,
    use_async: bool,
    formatter: Callable[[List[dict]], None],
    empty_message: str,
) -> None:
    """Execute one example query and print whatever it returned."""
    print("=" * 60)
    print(heading)
    print("=" * 60)
    print(f"\nQuery: {query.strip()}")
    print(f"\nExecuting {'async search ' if use_async else ''}(all time)...")

    try:
        if use_async:
            results = client.search_async(query=query, earliest_time="0", latest_time="now", max_results=10, max_wait=60)
        else:
            results = client.search(query=query, earliest_time="0", latest_time="now", max_count=20)
    except TimeoutError:
        print("⏱️  Query timed out - try reducing time range")
        return
    except Exception as e:
        print(f"❌ Query failed: {e}")
        return

    if results:
        formatter(results)
    else:
        print(empty_message)
    print()


def main() -> None:
    """Execute example threat hunting queries."""
    print("🔍 Hecate Splunk Integration Example\n")

    client = _connect()
    if client is None or not _show_connection(client):
        return

    _show_indexes(client)

    for heading, query, use_async, formatter, empty_message in EXAMPLES:
        _run_example(client, heading, query, use_async, formatter, empty_message)

    print("\n" + "=" * 60)
    print("✅ Example complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  • Modify queries for your environment")
    print("  • Add to hunt files in hunts/ directory")
    print("  • Use 'hecate-agent splunk search' for CLI execution")
    print("  • See integrations/quickstart/splunk-api.md for more examples")


if __name__ == "__main__":
    main()

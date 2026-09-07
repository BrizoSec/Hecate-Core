"""Regression: the CLI aborted on a legacy Windows console.

`athf hunt new` exited 1 on every Windows CI job without creating the hunt:

    File "athf/commands/_hunt_create.py", line 117, in new
      console.print("\\n[bold cyan]\\U0001f3af Creating new hunt[/bold cyan]\\n")
    ...
    File "lib/encodings/cp1252.py", line 19, in encode
    UnicodeEncodeError: 'charmap' codec can't encode character '\\U0001f3af'

A legacy Windows console encodes as cp1252, which cannot represent the emoji
and box-drawing characters this CLI prints; rich writes through the stream, so
the first such character aborted the command before it did any real work. 27
source files emit characters outside cp1252, so the entry point makes the
streams capable once rather than every message being stripped.

The tests below force a cp1252 stream on any platform, so they exercise the
real failure without needing Windows.
"""

import io
import sys

import pytest

from athf.cli import _ensure_printable_stdio


def _cp1252_stream():
    """A text stream that behaves like a legacy Windows console."""
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


@pytest.mark.unit
class TestStdioIsMadePrintable:
    def test_cp1252_stdout_is_reconfigured_to_utf8(self, monkeypatch):
        monkeypatch.setattr(sys, "stdout", _cp1252_stream())
        monkeypatch.setattr(sys, "stderr", _cp1252_stream())

        _ensure_printable_stdio()

        assert sys.stdout.encoding == "utf-8"
        assert sys.stderr.encoding == "utf-8"

    def test_emoji_survives_a_cp1252_stream_after_the_fix(self, monkeypatch):
        """The actual failing line from _hunt_create.new()."""
        monkeypatch.setattr(sys, "stdout", _cp1252_stream())
        _ensure_printable_stdio()

        from rich.console import Console

        Console(file=sys.stdout, soft_wrap=True).print("\U0001f3af Creating new hunt")
        sys.stdout.flush()

        assert "\U0001f3af".encode("utf-8") in sys.stdout.buffer.getvalue()

    def test_emoji_would_crash_without_the_fix(self, monkeypatch):
        """Pins the failure the fix exists for -- if this stops raising, the
        reconfiguration is no longer what is protecting the CLI."""
        monkeypatch.setattr(sys, "stdout", _cp1252_stream())

        from rich.console import Console

        with pytest.raises(UnicodeEncodeError):
            Console(file=sys.stdout, soft_wrap=True).print("\U0001f3af Creating new hunt")
            sys.stdout.flush()

    def test_a_stream_that_refuses_utf8_still_stops_aborting(self, monkeypatch):
        """If the encoding cannot be changed, relaxing the error handler is the
        fallback: losing a glyph to a placeholder is acceptable, aborting the
        command halfway through its output is not."""
        stream = _cp1252_stream()
        real_reconfigure = stream.reconfigure

        def _refuse_encoding_changes(**kwargs):
            if "encoding" in kwargs:
                raise ValueError("encoding cannot be changed on this stream")
            return real_reconfigure(**kwargs)

        monkeypatch.setattr(stream, "reconfigure", _refuse_encoding_changes)
        monkeypatch.setattr(sys, "stdout", stream)

        _ensure_printable_stdio()

        assert sys.stdout.encoding == "cp1252"
        assert sys.stdout.errors == "replace"

        # The character is lost, but the command keeps running.
        sys.stdout.write("\U0001f3af ok\n")
        sys.stdout.flush()
        assert b"ok" in stream.buffer.getvalue()

    def test_a_stream_without_reconfigure_is_left_alone(self, monkeypatch):
        """Capture layers (pytest, click's CliRunner) swap in objects that are
        not TextIOWrapper; they must not be touched or crashed on."""

        class _Plain:
            encoding = "ascii"

            def write(self, text):
                return len(text)

        plain = _Plain()
        monkeypatch.setattr(sys, "stdout", plain)
        monkeypatch.setattr(sys, "stderr", plain)

        _ensure_printable_stdio()

        assert sys.stdout is plain
        assert sys.stdout.encoding == "ascii"

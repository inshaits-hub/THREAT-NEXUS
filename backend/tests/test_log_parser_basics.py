"""Small, focused edge-case tests for the log parser."""

from datetime import datetime

from src import log_parser


def test_parse_lines_skips_invalid_input_and_keeps_valid_events_in_order():
    lines = [
        "not a log line",
        "Sep 28 09:20:00 fw01 kernel: first event",
        "",
        "Sep 28 09:21:00 fw01 kernel: second event",
    ]

    events = log_parser.parse_lines(lines)

    assert [event["message"] for event in events] == ["first event", "second event"]


def test_parse_text_with_no_log_lines_returns_empty_list():
    assert log_parser.parse_text("") == []
    assert log_parser.parse_text("\n  \n") == []


def test_parse_timestamp_converts_timezone_to_utc():
    timestamp = log_parser.parse_timestamp("2026-09-28T03:05:00+03:00")

    assert timestamp == datetime(2026, 9, 28, 0, 5, 0)
    assert timestamp.tzinfo is None


def test_parse_file_replaces_invalid_utf8_bytes(tmp_path):
    log_file = tmp_path / "corrupt.log"
    log_file.write_bytes(b"Sep 28 09:20:00 fw01 kernel: note \xff\n")

    events = log_parser.parse_file(str(log_file))

    assert len(events) == 1
    assert ord(events[0]["message"][-1]) == 0xFFFD

def test_event_time_returns_none_for_non_dictionary_input():
    assert log_parser.event_time(None) is None
    assert log_parser.event_time("not an event") is None

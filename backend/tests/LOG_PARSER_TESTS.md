# Log Parser: Quick Test Guide

These five small tests cover common edge cases for `src/log_parser.py`.
Existing format-specific parser tests remain in `test_parser.py`.

| Test | What it checks |
|---|---|
| Skips invalid lines | Valid events are returned in order; unrelated lines and blanks are skipped |
| Empty text | Empty or blank-only input returns no events |
| Timezone conversion | Offset timestamps are converted to naive UTC |
| Corrupt file bytes | Invalid UTF-8 is replaced instead of stopping file parsing |
| Invalid event value | `event_time` returns `None` for non-dictionary input |

Run from the `backend` directory in PowerShell:

```powershell
python -m pytest tests\test_log_parser_basics.py -v
```

Run all parser tests (including the existing format-specific tests):

```powershell
python -m pytest tests\test_parser.py tests\test_log_parser_basics.py -v
```

# Alert Manager Test Plan

## Scope

This plan covers `src/alert_manager.py`: severity normalization, risk-score
fallback, badge assignment, alert deduplication, ordering, severity counts,
attempt/risk normalization, and the frontend payload contract. It does not
test threat detection rules or API/database behavior; those are covered by
the other backend tests.

## Test cases

| ID | Scenario | Expected result |
|---|---|---|
| AM-01 | Severity aliases, whitespace/case normalization, score thresholds, invalid labels/scores | A canonical severity is returned (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`) |
| AM-02 | Badge for each canonical severity | `CRITICAL=red`, `HIGH=orange`, `MEDIUM=yellow`, `LOW=blue` |
| AM-03 | Same IP and rule at exactly 120 seconds apart | One alert; occurrences and attempts are summed; highest severity/risk is retained; time window is 120 seconds |
| AM-04 | Same IP and rule 121 seconds apart | Two independent alerts |
| AM-05 | Same timestamp but different IP or rule | Alerts do not merge across either grouping boundary |
| AM-06 | Missing or unrecognized timestamps | Events cannot be time-correlated and remain separate |
| AM-07 | Different severities and risks | Alerts sort by severity rank, then descending risk score |
| AM-08 | Out-of-range risk scores and invalid/negative attempts | Risk is clamped to 0–100; attempts are at least 1 |
| AM-09 | Mixed severity counts and empty input | All four buckets are present and counts use canonical severities |
| AM-10 | Alert presentation contract | Title, badge, timestamps, and structured payload fields are populated consistently |

## Run

From `backend/` in PowerShell:

```powershell
python -m pytest tests\test_alert_manager.py -v
```

Run the full backend suite with:

```powershell
python -m pytest
```

The focused test module is `tests/test_alert_manager.py`. Shared coverage for
the threat detection pipeline and alert handling remains in
`tests/test_threats.py`.

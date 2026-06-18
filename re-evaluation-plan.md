# Re-evaluation Plan: STREAM_DATA_BLOCKED / DATA_BLOCKED Sections

## Overview
This plan re-evaluates all RFC sections that mention STREAM_DATA_BLOCKED or DATA_BLOCKED for thorough re-examination, outputting results to findings_2.csv.

## Sections to Re-evaluate

The following **9 unique RFC sections** contain findings mentioning STREAM_DATA_BLOCKED or DATA_BLOCKED in findings.csv:

| # | RFC Section | Finding Count |
|---|-------------|---------------|
| 1 | RFC 9000 §3.1 | 2 (lines 9, 12) |
| 2 | RFC 9000 §3.2 | 2 (lines 13, 24) |
| 3 | RFC 9000 §3.3 | 3 (lines 25, 27, 28) |
| 4 | RFC 9000 §4.1 | 2 (lines 64, 65) |
| 5 | RFC 9000 §4.2 | 1 (line 71) |
| 6 | RFC 9000 §13.3 | 1 (line 551) |
| 7 | RFC 9000 §19.12 | 6 (lines 838-843) |
| 8 | RFC 9000 §19.13 | 6 (lines 844-849) |
| 9 | RFC 9000 §22.4 | 2 (lines 1111-1112) |

## Execution Strategy

Sequential, one section at a time:

1. `task(description="Review RFC 9000 §3.1", prompt="Review RFC 9000 section 3.1", subagent_type="rfc-reviewer")` → append to findings_2.csv
2. `task(description="Review RFC 9000 §3.2", prompt="Review RFC 9000 section 3.2", subagent_type="rfc-reviewer")` → append to findings_2.csv
3. `task(description="Review RFC 9000 §3.3", prompt="Review RFC 9000 section 3.3", subagent_type="rfc-reviewer")` → append to findings_2.csv
4. `task(description="Review RFC 9000 §4.1", prompt="Review RFC 9000 section 4.1", subagent_type="rfc-reviewer")` → append to findings_2.csv
5. `task(description="Review RFC 9000 §4.2", prompt="Review RFC 9000 section 4.2", subagent_type="rfc-reviewer")` → append to findings_2.csv
6. `task(description="Review RFC 9000 §13.3", prompt="Review RFC 9000 section 13.3", subagent_type="rfc-reviewer")` → append to findings_2.csv
7. `task(description="Review RFC 9000 §19.12", prompt="Review RFC 9000 section 19.12", subagent_type="rfc-reviewer")` → append to findings_2.csv
8. `task(description="Review RFC 9000 §19.13", prompt="Review RFC 9000 section 19.13", subagent_type="rfc-reviewer")` → append to findings_2.csv
9. `task(description="Review RFC 9000 §22.4", prompt="Review RFC 9000 section 22.4", subagent_type="rfc-reviewer")` → append to findings_2.csv

## Key Design Notes

- **Prompt format**: `"Review RFC 9000 section X.X"` — no assumptions about requirements, let the agent decide what to look for (per run-review-example.md)
- **Sequential execution**: Each agent runs → output captured → appended to findings_2.csv → next agent runs
- **Output file**: findings_2.csv (new, separate from original findings.csv)
- **Finding format** (per agent output): `RFC 9000|X.X|<requirement>|<Y|N|PARTIAL>|<explanation>`

## Files Created

- run-review-example.md - Original review example plan
- findings.csv - Original findings (1148 lines)
- findings_2.csv - New findings from re-evaluation (to be created)
- re-evaluation-plan.md - This plan document

## Commands to Execute

For each section X.X, run:

task(description="Review RFC 9000 section X.X", prompt="Review RFC 9000 section X.X", subagent_type="rfc-reviewer")

Then append output to findings_2.csv:

cat >> findings_2.csv << 'EOF'
# (section X.X findings here)
EOF

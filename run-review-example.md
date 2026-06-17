# RFC Review Example Plan

## Step 1 — Launch rfc-reviewer subagent for RFC 9000 section 3.3

Call `task` with `subagent_type="rfc-reviewer"`:

```
task(description="Review RFC 9000 section 3.3", prompt="Review RFC 9000 section 3.3", subagent_type="rfc-reviewer")
```

---

## Step 2 — Append section 3.3 findings to findings.csv

The agent returns pipe-delimited findings in this format:

```
RFC 9000|3.3|<requirement>|<Y|N|PARTIAL>|<explanation>
```

Append them to `/home/dylanetaft/projects/YAWT/findings.csv`:

```bash
cat >> /home/dylanetaft/projects/YAWT/findings.csv << 'EOF'
# (section 3.3 findings here)
EOF
```

---

## Step 3 — Launch rfc-reviewer subagent for RFC 9000 section 3.4

```
task(description="Review RFC 9000 section 3.4", prompt="Review RFC 9000 section 3.4", subagent_type="rfc-reviewer")
```

---

## Step 4 — Append section 3.4 findings to findings.csv

```bash
cat >> /home/dylanetaft/projects/YAWT/findings.csv << 'EOF'
# (section 3.4 findings here)
EOF
```

---

## Step 5 — Launch rfc-reviewer subagent for RFC 9000 section 3.5

```
task(description="Review RFC 9000 section 3.5", prompt="Review RFC 9000 section 3.5", subagent_type="rfc-reviewer")
```

---

## Step 6 — Append section 3.5 findings to findings.csv

```bash
cat >> /home/dylanetaft/projects/YAWT/findings.csv << 'EOF'
# (section 3.5 findings here)
EOF
```

---

## Key design note

The `prompt` is just `"Review RFC 9000 section X.X"` — no assumptions about what the RFC contains, no lists of requirements to check. Let the agent decide what to look for.

This is fully sequential: agent runs → output appended → next agent runs → output appended. This prevents the loop from getting stuck if one agent hangs.

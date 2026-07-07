# Campaign Metrics — GoPhish Phishing Simulation (Lab 6)

Personal lab. Aggregate counts only. No captured credentials, no real
addresses, no per-user data — the target was a single self-owned test mailbox.

## Funnel

| Stage | Count |
|---|---|
| Emails sent | 1 |
| Opened (tracking pixel) | 1 |
| Link clicked | 1 |
| Data submitted (test creds) | 1 |
| Reported | 0 |

## Time-to-Compromise

| Event | Time (local) |
|---|---|
| Email sent | 17:18:32 |
| Opened / Clicked (landing page loaded) | 17:19:25 |
| Data submitted | 17:19:32 |
| **Send → submit** | **60 seconds** |

The tracking-pixel open collapsed into the single landing-page `GET`, so open
and click share a timestamp.

## Corroboration

The same 60-second timeline was confirmed across three independent sources,
agreeing to the second:

1. Raw GoPhish access log (on the attacker VM)
2. Splunk correlation on the recipient ID (`rid=JZgWFhx`)
3. GoPhish's own database CSV export (once UTC converted to local)

## Interpretation

With a single self-owned target, these counts demonstrate the **funnel and the
detection path**, not real-world awareness rates (n = 1). The value of the lab is
the end-to-end chain — build → compromise in 60 seconds → detect in the SIEM —
not a statistical click-rate study.

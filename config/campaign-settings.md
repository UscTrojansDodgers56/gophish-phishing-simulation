# Campaign Configuration — GoPhish Phishing Simulation (Lab 6)

Personal lab. Documented for reproducibility and detection context.
All credentials are redacted; all targets are self-owned test accounts,
shown here as placeholders. Nothing in this file is live or deployable.

## Sending Profile (SMTP)

| Setting | Value |
|---|---|
| Name | IT Support |
| From | `IT Support <sender@lab.local>` |
| Host | `<REDACTED>` |
| Username | `<REDACTED>` |
| Password | `<REDACTED>` |
| TLS | Enabled |

## Email Template

| Setting | Value |
|---|---|
| Name | Password Reset Lure |
| Subject | Action Required: Your Password Expires in 24 Hours |
| Tracking image | Enabled (1×1 pixel, `{{.TrackingURL}}`) |
| Link | `{{.URL}}` → landing page |

## Landing Page

| Setting | Value |
|---|---|
| Name | Reset Your Password |
| Capture submitted data | Enabled in lab; **neutralized in repo** (see `templates/landing-page.html`) |
| Capture passwords | Lab only — no captured values retained or committed |
| Redirect | none |

## Target Group

| Setting | Value |
|---|---|
| Name | Lab Test Target |
| Members | 1 |
| Target | `user1@lab.local` (self-owned test mailbox) |

## Campaign

| Setting | Value |
|---|---|
| Name | Password Reset Simulation |
| Sending profile | IT Support |
| Template | Password Reset Lure |
| Landing page | Reset Your Password |
| Group | Lab Test Target |
| Launch | Immediate, fired at the self-owned test inbox only |

---

**Safety note:** real SMTP host/credentials, the GoPhish admin password, and the
real sender/target mailboxes are intentionally excluded or replaced. This file
records *how the campaign was structured*, not anything that could re-arm it.

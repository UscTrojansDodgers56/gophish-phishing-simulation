# GoPhish Phishing Simulation & Detection

A phishing campaign built, launched against my own test accounts only, and then detected in my own SIEM, no real people were ever targeted. I designed the lure, ran it end to end, compromised a self-owned test mailbox in 60 seconds, then forwarded the logs into Splunk and wrote the detection that catches it. This is Lab 6 of a self-directed SOC detection series.

**Series progression:** the offensive and detection flip side of this email teardown. together they cover both sides of initial access, from analyzing a real phish to building one and detecting it.

| | |
|---|---|
| **Type** | Phishing simulation (offense) + detection (defense) |
| **Tools** | GoPhish v0.12.1, Splunk, Ubuntu Server VMs (VMware) |
| **Targets** | Self-owned test accounts ONLY — see Authorization & Ethics |
| **Method** | Plan → Build → Launch → Track → Report, then Detect → Analyze → Correlate → Harden → Validate |

---

## ⚠️ Authorization & Ethics

This is a personal lab.

- Every email was sent **only to test accounts I own and control**. No real person, coworker, or third party was ever targeted.
- **No real credentials were captured** — the only values submitted were fake test strings I typed into my own test inbox. None of them are in this repo.
- Running a phishing test against real people requires **written organizational authorization**, which I did not have and did not seek — so I never went near real targets.
- The landing page in this repo has its **credential-capture action neutralized** (`action="#LAB-ONLY-CAPTURE-DISABLED"`). It is an educational artifact demonstrating technique and detection — **not a deployable phishing kit**.
- All infrastructure was private and contained: GoPhish on a NAT'd VM (private `192.168.220.x` addressing), the capture page never reachable from the internet.

The point of this lab is to understand the attacker's technique from the inside **and then prove I can detect it** — not to hand anyone a working harvester.

---

## Disclaimer

This is a personal home lab, not professional SOC experience. The campaign, targets, and "victim" are all mine. Because the target list was a single self-owned mailbox, the click/submit counts here demonstrate the **funnel and the detection**, not real-world awareness rates (n = 1, not a training-metrics study). Everything is framed honestly: simulated attack, self-owned accounts, real detection logic written and validated against the real campaign data.

---

## Environment

| Item | Value |
|---|---|
| Attacker infrastructure | GoPhish v0.12.1 on its own Ubuntu Server VM, NAT'd and isolated |
| SIEM | Splunk on a **separate** VMware Ubuntu VM (telemetry has to travel; the SIEM never shares a box with the attacker) |
| Mail handling | Two self-owned test mailboxes — a real sender and a real target, both mine (shown as placeholders in this repo) |
| Analyst host | Windows 11 for review |
| Network | Private lab addressing (`192.168.220.x`); NAT keeps the capture page unreachable from the internet |

---

## Part 1 — Build & Run the Campaign (Plan → Build → Launch → Track → Report)

| Phase | What I did |
|---|---|
| **Plan** | Chose a password-reset lure (boring on purpose — boring is what people click). Target list = one self-owned test mailbox. |
| **Build** | Stood up GoPhish v0.12.1; configured a sending profile; wrote an email template with a 1×1 tracking pixel (`{{.TrackingURL}}`) and a tracked link (`{{.URL}}`); cloned a "Reset Your Password" landing page that captures submitted data locally. |
| **Launch** | Fired the campaign at my own test inbox only. Subject: *"Action Required: Your Password Expires in 24 Hours."* |
| **Track** | Watched the dashboard funnel light up stage by stage as the tracking pixel and link events came in. |
| **Report** | Exported the campaign report (CSV) and reconciled every stage against the raw log. |

The full visual walkthrough — console, template, landing page, funnel, and detection — lives in the linked LinkedIn carousel (`gophish-splunk-carousel.pdf`).

---

## Campaign Results

Aggregate counts only — no captured data.

| Metric | Count |
|---|---|
| Emails sent | 1 |
| Opened (tracking pixel) | 1 |
| Link clicked | 1 |
| Data submitted (test creds) | 1 |
| Reported | 0 |

**Time-to-compromise: 60 seconds** — from email sent to credentials submitted.

---

## Part 2 — Detect the Campaign (Detect → Analyze → Correlate → Harden → Validate)

| Phase | What I did |
|---|---|
| **Detect** | Forwarded GoPhish's access log off the attacker VM into Splunk, ingested under a custom sourcetype (`gophish_access`). Found the campaign in the logs: the send event, the web hit, the credential POST. |
| **Analyze** | Parsed each layer — the `"Email sent"` event, the `GET /?rid=` landing-page load (open + click), and the `POST /?rid=` credential submission. |
| **Correlate** | Stitched send, open/click, submit into one timeline with `rex` + `stats`, keyed on the target so the send event stayed in scope. |
| **Harden** | Identified the controls a real org would use to blunt this (below). |
| **Validate** | Cross-checked the computed timeline against three independent sources and the raw log, the Splunk correlation on the recipient ID, and GoPhish's own CSV export, all agreeing to the second. |

### Detection Logic

Custom sourcetype ingestion, `rex` field extraction, and SPL that computes time-to-compromise straight from the data:

```spl
sourcetype=gophish_access "Email sent" OR "rid="
| rex field=_raw "rid=(?<rid>\w+)"
| rex field=_raw "\"(?<method>GET|POST) "
| rex field=_raw "email=\"[^<]*<(?<sent_email>[^>]+)>\""
| eval stage=case(match(_raw, "Email sent"), "Sent", method=="GET", "Opened/Clicked", method=="POST", "Submitted")
| eval target_email=coalesce(sent_email, "user1@lab.local")
| stats earliest(_time) as first_seen, latest(_time) as last_seen, values(stage) as stages by target_email
| eval time_to_compromise=last_seen-first_seen
| convert ctime(first_seen) ctime(last_seen)
| table target_email, stages, first_seen, last_seen, time_to_compromise
```

**A note on the number, because I checked it.** An earlier version of this query keyed on `rid` alone and returned **7 seconds** — wrong, because the `"Email sent"` event carries no `rid`, so it only measured from the click. Coalescing on the target email pulled the send event back into scope and produced the real minute. The query above reports **61s** because it anchors one second early on a dashboard-poll request; the true send→submit gap is exactly **60s** (`17:18:32` → `17:19:32`). Both numbers are documented in `detection/gophish-detection.spl`, not hand-waved.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Phishing | T1566 | The password-reset campaign itself |
| Spearphishing Link | T1566.002 | The tracked `{{.URL}}` link → cloned landing page |
| User Execution: Malicious Link | T1204.001 | The target's `GET /?rid=` landing-page load |
| Input Capture: Web Portal Capture | T1056.003 | The `POST /?rid=` credential submission on the fake login page |

---

## Hardening & Awareness Recommendations

What would reduce click/submit and blunt the impact in a real org — with a Tier-1-honest split between what an analyst *does* on the alert versus what leadership *implements*:

- **On the alert (analyst):** flag the submit event, escalate the account as compromised, trigger a forced password reset and session/token revocation, and recommend an awareness follow-up for the user.
- **Email layer (implement):** enforce DMARC at `p=reject` with aligned SPF/DKIM; sandbox and rewrite links at the gateway; flag newly-registered sender domains.
- **Identity layer (implement):** phishing-resistant MFA so a captured password alone isn't enough — the single highest-leverage control against exactly this attack.
- **People layer (the actual point of simulations):** recurring awareness training and an easy one-click report button, measured over time.
- **Detection layer:** the SPL above, scheduled as a correlation search, so a send→submit funnel against a user raises an alert in the SIEM the way it did here.

---

## Timeline

The campaign's own funnel, as a chronology:

```
17:18:32   Email sent — password-reset lure delivered          T1566.002
17:19:25   Opened / Clicked — landing page loaded (tracked link) T1204.001
17:19:32   Submitted — test credentials captured (contained)    T1056.003

           Time-to-compromise: 60 seconds
```

(The tracking-pixel open collapsed into the single landing-page `GET`, which is why open and click share a timestamp.)

---

## Repo Structure

```
gophish-phishing-simulation/
├── README.md
├── LICENSE
├── templates/
│   ├── email-template.html          (lure email, tracking placeholders)
│   └── landing-page.html            (CAPTURE NEUTRALIZED — lab artifact only)
├── config/
│   └── campaign-settings.md         (sending profile + group; creds REDACTED, targets = placeholders)
├── detection/
│   └── gophish-detection.spl        (Part 2 Splunk detection + time-to-compromise)
├── results/
│   └── campaign-metrics.md          (aggregate counts only, no captured data)
└── gophish-splunk-carousel.pdf      (LinkedIn carousel — visual walkthrough)
```

---

## Author

Sean White — [LinkedIn](https://linkedin.com/in/seanwhite56) · [GitHub](https://github.com/UscTrojansDodgers56)

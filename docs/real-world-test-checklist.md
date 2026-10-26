# ADX Group (adxgroup.tech) — Pre-Launch Real-World Verification Checklist

**Audience:** Founder & Operational Testers (Step-by-step beginner guide)  
**Target:** https://adxgroup.tech  
**Date of Testing:** [YYYY-MM-DD]  
**Tester Name:** [Founder / QA Tester]  

Complete each verification step below prior to public announcement or campaign launch. Record the result in the **Status** column and document any notes.

---

## Pre-Launch Verification Matrix

| # | Test Item | Step-by-Step Instructions | Expected Result | Status (PASS / FAIL) | Notes / Observations |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **1** | **Contact Form Inbound Delivery** | 1. Open `https://adxgroup.tech/#contact` on a mobile phone.<br>2. Fill in a test name, a real secondary personal email (e.g. your personal `@gmail.com`), and a test message.<br>3. Submit the form.<br>4. Open your `contact@adxgroup.tech` webmail inbox (via Zoho Mail).<br>5. Check both the Primary Inbox and Spam/Junk folders within 5 minutes. | Form shows green confirmation message. Inquiry details arrive in `contact@adxgroup.tech` without silent loss or bouncing. | `[ &nbsp; ]` | *Note: If SMTP_PASSWORD is not set in Vercel env, inquiry is logged in data/leads.json; add SMTP credentials in Vercel to deliver live.* |
| **2** | **WhatsApp Click-to-Chat Link** | 1. Navigate to `https://adxgroup.tech` on mobile and desktop.<br>2. Click the floating green WhatsApp button in the bottom right corner.<br>3. Also test the "Chat on WhatsApp" buttons in the Hero section and final CTA block. | WhatsApp opens directly to a chat window with `+234 913 616 8678`. The prefilled message: *"Hello ADX Group, I would like to inquire about the ADX Shield Email Security Baseline Assessment for my organization."* is pre-populated in the text box. | `[ &nbsp; ]` | |
| **3** | **Zero Placeholders Audit** | 1. Open each public route in Chrome/Firefox:<br>&bull; `/`<br>&bull; `/solutions/shield`<br>&bull; `/solutions/comply`<br>&bull; `/solutions/resilience`<br>&bull; `/solutions/ai-automation`<br>&bull; `/readiness-check`<br>&bull; `/security`<br>&bull; `/privacy`<br>&bull; `/terms`<br>&bull; `/cookies`<br>&bull; `/do-not-sell`<br>2. On every page, press `Ctrl + F` (or `Cmd + F` on Mac).<br>3. Search for the exact word `PLACEHOLDER`. | Search returns **0 matches** on every single public page. No bracketed placeholder instructions appear anywhere in text, attributes, or footer. | `[ &nbsp; ]` | *Automated test: `python test_placeholder_guard.py` must also report 100% PASS.* |
| **4** | **Navigation & Link Integrity** | 1. On desktop (1280px screen), verify the top header fits completely on one single line.<br>2. Click each menu link: *Solutions*, *Readiness Check*, *How We Work*, *FAQ*, *Sign In*, *Run Free Audit*.<br>3. Scroll down to the 4-column footer and click every single link:<br>&bull; The 4 solution links<br>&bull; Free Readiness Self-Check<br>&bull; Security & Control Principles<br>&bull; Privacy Policy, Terms, Cookie Notice, Do Not Sell. | Zero 404 errors. Every link opens its corresponding valid page or smoothly scrolls to the target anchor section. | `[ &nbsp; ]` | |
| **5** | **Mobile Responsiveness & Viewport Scroll** | 1. Open `https://adxgroup.tech` on a smartphone (or use Chrome DevTools set to iPhone SE / 360px width).<br>2. Scroll from top to bottom.<br>3. Verify there is **no horizontal scrolling or side-to-side wobble**.<br>4. Tap the hamburger menu button in the top header. | Hamburger menu smoothly expands and collapses. All buttons and form inputs are comfortably tappable (minimum 44px tap height). Brand tagline is cleanly hidden on mobile so header remains uncrowded. | `[ &nbsp; ]` | |
| **6** | **Outbound Email Authentication (SPF / DKIM / DMARC)** | 1. Log into your Zoho webmail for `contact@adxgroup.tech`.<br>2. Compose a new email and send it to a personal Google account (`yourname@gmail.com`).<br>3. In Gmail, open the received email.<br>4. Click the three dots menu (More options) next to the reply button and select **"Show original"**.<br>5. Review the header summary box at the top. | The header summary displays:<br>&bull; **SPF:** `PASS` with IP of Zoho mail servers.<br>&bull; **DKIM:** `PASS` with domain `adxgroup.tech`.<br>&bull; **DMARC:** Confirm policy behavior once DMARC TXT record is published in Cloudflare DNS. | `[ &nbsp; ]` | *Crucial step: Add `_dmarc.adxgroup.tech` TXT record `v=DMARC1; p=quarantine; rua=mailto:contact@adxgroup.tech` in Cloudflare.* |

---

## Operational Sign-Off

- **All 6 Tests Passed:** Yes `[ ]` &nbsp;&nbsp; No `[ ]`
- **Follow-up Remediations Required:**
  1. __________________________________________________________________
  2. __________________________________________________________________
- **Approved for Launch by:** ___________________________ &nbsp;&nbsp;&nbsp;&nbsp; **Date:** _______________

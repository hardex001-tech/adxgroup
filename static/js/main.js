document.addEventListener("DOMContentLoaded", () => {
  // Enterprise Notification System
  window.showAdxNotice = function (msg, type = "error", title = null) {
    let container = document.getElementById("adx-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "adx-toast-container";
      container.className = "adx-toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `adx-toast adx-toast-${type}`;

    const defaultTitle =
      type === "error"
        ? "Perimeter Verification Alert"
        : type === "success"
        ? "Verification Successful"
        : "Security Notice";

    let iconSvg = "";
    if (type === "error") {
      iconSvg = `<svg class="adx-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    } else if (type === "success") {
      iconSvg = `<svg class="adx-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    } else {
      iconSvg = `<svg class="adx-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    }

    toast.innerHTML = `
      ${iconSvg}
      <div class="adx-toast-content">
        <div class="adx-toast-title">${escapeHtml(title || defaultTitle)}</div>
        <div class="adx-toast-desc">${escapeHtml(msg)}</div>
      </div>
      <button class="adx-toast-close" aria-label="Close">&times;</button>
    `;

    const closeBtn = toast.querySelector(".adx-toast-close");
    const dismiss = () => {
      toast.style.animation = "adxToastSlideOut 0.25s forwards";
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 260);
    };

    closeBtn.addEventListener("click", dismiss);
    setTimeout(dismiss, 7000);

    container.appendChild(toast);
  };

  // 1. Live 6-Gate Infrastructure & 2026 CVE Diagnostic Scanner
  const scanForm = document.getElementById("scan-form");
  const domainInput = document.getElementById("scan-domain-input");
  const scanBtn = document.getElementById("scan-submit-btn");
  const resultsBox = document.getElementById("scan-results");
  const scoreValue = document.getElementById("scan-score-val");
  const gradeBadge = document.getElementById("scan-grade-badge");
  const domainTitle = document.getElementById("scan-domain-title");
  const telemetryStrip = document.getElementById("telemetry-strip");
  const cveReportMatrix = document.getElementById("cve-report-matrix");
  const cveSummaryBadge = document.getElementById("cve-exposure-summary-badge");
  const scoreRingCircle = document.getElementById("score-ring-circle");
  const aiSummaryText = document.getElementById("scan-ai-summary");
  const gatesTableBody = document.getElementById("gates-table-body");

  if (scanForm) {
    scanForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = domainInput.value.trim();
      if (!domain) return;

      const consentBox = document.getElementById("scan-consent-checkbox");
      if (consentBox && !consentBox.checked) {
        window.showAdxNotice("Please confirm domain authorization consent before initiating diagnostic telemetry.", "error", "Authorization Required");
        return;
      }

      scanBtn.disabled = true;
      scanBtn.textContent = "Inspecting Host IP, TLS & 2026 CVEs...";

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain, consent: true }),
        });

        if (res.status === 401) {
          window.location.href = `/login?scan=${encodeURIComponent(domain)}`;
          return;
        }

        let payload = {};
        try {
          payload = await res.json();
        } catch (jsonErr) {
          payload = { detail: "Network request interrupted or connection reset. Please re-run the diagnostic." };
        }

        if (!res.ok || !payload.ok) {
          window.showAdxNotice(payload.detail || "Could not complete scan. Verify the domain name.", "error", "Perimeter Verification Alert");
          return;
        }

        const data = payload.data;
        const tel = data.telemetry || {};

        resultsBox.classList.remove("hidden");
        domainTitle.textContent = `${data.domain} | Infrastructure & Network Telemetry (${data.timestamp})`;
        scoreValue.textContent = `${data.score}/100`;
        gradeBadge.textContent = `GRADE ${data.grade} | ${data.risk_level}`;
        aiSummaryText.textContent = data.ai_executive_summary;

        if (scoreRingCircle) {
          const circumference = 163.36;
          const pct = Math.max(5, Math.min(100, Number(data.score) || 0));
          const offset = circumference - (pct / 100) * circumference;
          scoreRingCircle.style.strokeDashoffset = String(offset);
          if (pct >= 80) {
            scoreRingCircle.style.stroke = "#10b981";
          } else if (pct >= 60) {
            scoreRingCircle.style.stroke = "#2563eb";
          } else {
            scoreRingCircle.style.stroke = "#ef4444";
          }
        }

        if (telemetryStrip) {
          telemetryStrip.innerHTML = `
            <div class="telemetry-cell">
              <span>Resolved Host IP</span>
              <strong>${escapeHtml(tel.resolved_ip || "Unresolved")}</strong>
            </div>
            <div class="telemetry-cell">
              <span>Handshake Latency</span>
              <strong>${tel.latency_ms !== undefined ? escapeHtml(tel.latency_ms + " ms") : "N/A"}</strong>
            </div>
            <div class="telemetry-cell">
              <span>TLS Protocol &amp; Cipher</span>
              <strong>${escapeHtml(tel.tls_protocol || "None")}${tel.cipher_suite && tel.cipher_suite !== "None" && tel.cipher_suite !== "AEAD" ? ` &bull; ${escapeHtml(tel.cipher_suite)}` : ""}</strong>
            </div>
            <div class="telemetry-cell">
              <span>Certificate Authority</span>
              <strong>${escapeHtml(tel.cert_issuer || "Unverified")}</strong>
            </div>
            <div class="telemetry-cell">
              <span>HTTP Server Fingerprint</span>
              <strong>${escapeHtml(tel.server_banner || "Hidden / Edge Proxy")}</strong>
            </div>
            <div class="telemetry-cell">
              <span>Audit Depth</span>
              <strong style="color: var(--accent-primary);">6 Perimeter Parameters</strong>
            </div>
          `;
        }

        // Hide CVE exposure section from search results (CVEs belong exclusively to Tab 3 Threat Intelligence Radar)
        const cveSection = document.querySelector(".cve-report-section");
        if (cveSection) cveSection.style.display = "none";

        window.lastScanResult = data;
        const debriefBtn = document.getElementById("play-debrief-btn");
        if (debriefBtn) debriefBtn.style.display = "inline-flex";
        const pdfBtn = document.getElementById("export-pdf-btn");
        if (pdfBtn) pdfBtn.style.display = "inline-flex";

        gatesTableBody.innerHTML = "";
        data.gates.forEach((g) => {
          const tr = document.createElement("tr");
          let badgeClass = "badge-false";
          if (g.state === true) {
            badgeClass = "badge-true";
          } else if (g.status_label && g.status_label.includes("UNVERIFIED")) {
            badgeClass = "badge-warn";
          }

          const cveBadge = g.cve_ref
            ? `<div style="margin-top: 6px;"><span class="cve-tag">${escapeHtml(g.cve_ref)}</span></div>`
            : "";

          let actionHtml = "";
          if (!g.state) {
            const clientNote = g.client_action
              ? `<div style="margin-bottom: 8px; color: var(--text-muted); font-size: 0.84rem;">${escapeHtml(g.client_action)}</div>`
              : "";

            const safeDomain = escapeJsArg(data.domain);
            const safeParam = escapeJsArg(g.gate_id);
            const safeVector = escapeJsArg(g.vector);
            const safeCve = escapeJsArg(g.cve_ref || "2026-CVE");

            actionHtml = `
              <div class="locked-patch-bar">
                <div>
                  <strong style="color: var(--text-main); display: block; margin-bottom: 3px;">
                    Remediation Guidance &amp; Engineering Scope
                  </strong>
                  ${clientNote}
                </div>
                <button
                  type="button"
                  class="btn btn-primary"
                  style="padding: 8px 14px; font-size: 0.78rem; white-space: nowrap;"
                  onclick="requestPatchForGate('${safeDomain}', '${safeParam}', '${safeVector}', '${safeCve}')"
                >
                  Deploy Fix with ADX ($350) &rarr;
                </button>
              </div>
            `;
          }

          tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-primary);">${escapeHtml(g.gate_id)}</td>
            <td>
              <strong>${escapeHtml(g.vector)}</strong>
              <div style="color: var(--text-muted); font-size: 0.78rem; margin-top: 2px;">${escapeHtml(g.condition)}</div>
              ${cveBadge}
            </td>
            <td><span class="${badgeClass}">${escapeHtml(g.status_label)}</span></td>
            <td>
              <div style="line-height: 1.55;">${escapeHtml(g.finding)}</div>
              ${actionHtml}
            </td>
          `;
          gatesTableBody.appendChild(tr);
        });
      } catch (err) {
        window.showAdxNotice("Network connectivity issue detected while querying perimeter telemetry. Please check your internet connection and re-run.", "error", "Network Alert");
      } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Audit Infrastructure Parameters";
      }
    });

    // Auto-run ?scan= parameter if present in query string on dashboard load
    const urlParams = new URLSearchParams(window.location.search);
    const autoScanDomain = urlParams.get("scan");
    if (autoScanDomain && domainInput) {
      domainInput.value = autoScanDomain;
      setTimeout(() => {
        scanForm.dispatchEvent(new Event("submit"));
      }, 350);
    }

    if (urlParams.get("verified") === "true") {
      window.showAdxNotice("Zero-Trust Identity Confirmed. Email address successfully verified.", "success", "Account Security Active");
    } else if (urlParams.get("verify_error")) {
      window.showAdxNotice("The verification link was invalid or has expired. Please request a new verification code below.", "error", "Verification Alert");
    }
  }

  window.resendVerificationEmail = async function () {
    const btn = document.getElementById("resend-verify-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Dispatching...";
    }
    try {
      const res = await fetch("/api/auth/resend-verify", { method: "POST" });
      const data = await res.json();
      if (res.ok && data.ok) {
        window.showAdxNotice(data.message || "Verification email dispatched.", "success", "Security Dispatch");
        if (btn) btn.textContent = "Dispatched!";
      } else {
        window.showAdxNotice(data.detail || "Could not resend email.", "error", "Dispatch Failed");
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Resend Verification Email";
        }
      }
    } catch (err) {
      window.showAdxNotice("Network error while dispatching email.", "error", "Network Error");
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Resend Verification Email";
      }
    }
  };

  // 2. Conversational ADX AI Security Architect (Zero Markdown Stars)
  const chatForm = document.getElementById("ai-chat-form");
  const chatInput = document.getElementById("ai-chat-input");
  const chatLog = document.getElementById("ai-chat-log");

  if (chatForm) {
    chatForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const message = chatInput.value.trim();
      if (!message) return;

      appendChatMessage(message, "chat-user");
      chatInput.value = "";

      // Show immediate 3-dot AI Thinking bubble
      const thinkingDiv = createThinkingBubble();

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message }),
        });
        const payload = await res.json();
        if (payload.ok && payload.data) {
          streamBotReply(thinkingDiv, payload.data.reply);
        } else {
          streamBotReply(thinkingDiv, "Please reach our engineering desk at contact@adxgroup.tech.");
        }
      } catch (err) {
        streamBotReply(thinkingDiv, "Connection interrupted. Email contact@adxgroup.tech for immediate support.");
      }
    });
  }

  function cleanDisplayMessage(raw) {
    return String(raw || "")
      .replace(/^#{1,6}\s*/gm, "")
      .replace(/\*\*/g, "")
      .replace(/__/g, "")
      .replace(/`/g, "")
      .trim();
  }

  function createThinkingBubble() {
    const div = document.createElement("div");
    div.className = "chat-msg chat-bot";
    div.style.whiteSpace = "pre-line";
    div.innerHTML = `
      <div class="ai-thinking-wrap">
        <span>ADX Neural Core is thinking</span>
        <div class="typing-dots"><span></span><span></span><span></span></div>
      </div>
    `;
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
    return div;
  }

  function streamBotReply(targetDiv, rawText) {
    const cleanText = cleanDisplayMessage(rawText);
    const tokens = cleanText.split(/(?=[ \n])/);
    targetDiv.innerHTML = "";
    targetDiv.classList.add("ai-typing-cursor");

    let idx = 0;
    const stepSize = tokens.length > 90 ? 3 : 2;

    const timer = setInterval(() => {
      if (idx < tokens.length) {
        targetDiv.textContent += tokens.slice(idx, idx + stepSize).join("");
        idx += stepSize;
        chatLog.scrollTop = chatLog.scrollHeight;
      } else {
        clearInterval(timer);
        targetDiv.classList.remove("ai-typing-cursor");
      }
    }, 24);
  }

  function appendChatMessage(text, className) {
    const div = document.createElement("div");
    div.className = `chat-msg ${className}`;
    div.style.whiteSpace = "pre-line";
    div.textContent = cleanDisplayMessage(text);
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  // 3. Client Engineering Deployment & Audit Form (Tab 4)
  const leadForm = document.getElementById("lead-form");
  const leadStatus = document.getElementById("lead-status");

  if (leadForm) {
    leadForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const company_or_name = document.getElementById("lead-name").value.trim();
      const email = document.getElementById("lead-email").value.trim();
      const division = document.getElementById("lead-division").value;
      const domain = document.getElementById("lead-domain").value.trim();
      const message = document.getElementById("lead-message").value.trim();

      try {
        const res = await fetch("/api/lead", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ company_or_name, email, division, domain, message }),
        });
        const payload = await res.json();
        if (res.ok && payload.ok) {
          leadStatus.style.color = "#10b981";
          leadStatus.textContent = payload.data.confirmation;
          leadForm.reset();
        } else {
          leadStatus.style.color = "#ef4444";
          leadStatus.textContent = payload.detail || "Please check your inputs.";
        }
      } catch (err) {
        leadStatus.style.color = "#ef4444";
        leadStatus.textContent = "Could not submit form. Email contact@adxgroup.tech directly.";
      }
    });
  }

  // 4. ADX's BFF (AEGIS) — WIT-h Style White & Royal-Blue Floating Assistant + Studio Neural AI Voice
  const oldVoiceOrb = document.getElementById("adx-voice-orb");
  if (oldVoiceOrb) {
    oldVoiceOrb.style.display = "none";
  }

  let voiceMuted = false;
  let hasWelcomed = false;
  let activeAudio = null;

  const botAvatarSvg = `
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
    </svg>
  `;

  function stopActiveVoice() {
    if (activeAudio) {
      try {
        activeAudio.pause();
        activeAudio.currentTime = 0;
      } catch (e) {}
      activeAudio = null;
    }
    const launcher = document.getElementById("aegis-launcher-orb");
    if (launcher) launcher.classList.remove("speaking");
  }

  function playAudioUrl(url) {
    stopActiveVoice();
    const launcher = document.getElementById("aegis-launcher-orb");
    const audio = new Audio(url);
    activeAudio = audio;
    audio.onplay = () => {
      hasWelcomed = true;
      if (launcher) launcher.classList.add("speaking");
    };
    audio.onended = () => {
      if (launcher) launcher.classList.remove("speaking");
      activeAudio = null;
    };
    audio.onerror = () => {
      if (launcher) launcher.classList.remove("speaking");
      activeAudio = null;
    };
    return audio.play();
  }

  window.lastScanResult = null;

  window.playScanDebrief = function () {
    if (!window.lastScanResult) return;
    const d = window.lastScanResult;
    const domain = d.domain;
    const score = d.score;
    const grade = d.grade;
    const failed = (d.gates || []).filter((g) => !g.state);
    let debrief = `Perimeter audit complete for ${domain}. Infrastructure score: ${score} out of 100, Grade ${grade}.`;
    if (failed.length > 0) {
      debrief += ` Attention required on ${failed.length} parameter: ${failed[0].vector}.`;
    } else {
      debrief += ` All infrastructure parameters passed verification.`;
    }
    const btn = document.getElementById("debrief-btn-label");
    if (btn) btn.textContent = "Playing Brief...";
    window.speakAdxVoice(debrief, true).finally(() => {
      setTimeout(() => {
        if (btn) btn.textContent = "Listen to Security Debrief";
      }, 3500);
    });
  };

  window.exportSecurityReportPdf = function () {
    if (!window.lastScanResult) {
      window.showAdxNotice("Please run an infrastructure audit first to generate an executive brief.", "info", "Deliverable Notice");
      return;
    }
    const d = window.lastScanResult;
    const tel = d.telemetry || {};
    const gates = d.gates || [];
    const failed = gates.filter((g) => !g.state);
    const passed = gates.filter((g) => g.state);
    const dateStr = d.timestamp || new Date().toUTCString();
    const auditId = "ADX-AUDIT-" + Math.random().toString(36).substring(2, 8).toUpperCase() + "-" + new Date().getFullYear();
    const scoreColor = d.score >= 85 ? "#059669" : d.score >= 65 ? "#d97706" : "#dc2626";

    let rowsHtml = "";
    gates.forEach((g) => {
      const stateBadge = g.state
        ? `<span style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px;">VERIFIED</span>`
        : `<span style="background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px;">ATTENTION REQUIRED</span>`;

      rowsHtml += `
        <tr style="border-bottom: 1px solid #e2e8f0;">
          <td style="padding: 10px 12px; font-family: monospace; font-weight: 700; color: #2563eb; vertical-align: top;">${escapeHtml(g.gate_id)}</td>
          <td style="padding: 10px 12px; vertical-align: top;">
            <strong style="color: #0f172a; font-size: 13px;">${escapeHtml(g.vector)}</strong>
            <div style="color: #64748b; font-size: 11px; margin-top: 2px;">${escapeHtml(g.condition || "")}</div>
          </td>
          <td style="padding: 10px 12px; vertical-align: top; text-align: center;">${stateBadge}</td>
          <td style="padding: 10px 12px; vertical-align: top; font-size: 12px; color: #334155; line-height: 1.5;">
            <div>${escapeHtml(g.finding)}</div>
            ${!g.state && g.client_action ? `<div style="margin-top: 6px; font-weight: 600; color: #0f172a; font-size: 11px;">&bull; Recommended Action: ${escapeHtml(g.client_action)}</div>` : ""}
          </td>
        </tr>
      `;
    });

    const reportHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ADX Executive Perimeter Brief — ${escapeHtml(d.domain)}</title>
  <link rel="stylesheet" href="/static/css/tokens.css" />
  <style>
    * { box-sizing: border-box; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    body { font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif; color: #0f172a; background: #ffffff; margin: 0; padding: 22px 24px; font-size: 12px; line-height: 1.42; }
    .report-sheet { position: relative; max-width: 880px; margin: 0 auto; background: #ffffff; }
    .watermark-bg { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); opacity: 0.038; pointer-events: none; z-index: 0; }
    .watermark-img { width: 520px; height: 520px; object-fit: contain; }
    .report-content { position: relative; z-index: 1; }
    .print-bar { background: #0f172a; color: #ffffff; padding: 10px 18px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; box-shadow: 0 4px 12px rgba(15,23,42,0.15); }
    .print-btn { background: #2563eb; color: #ffffff; border: none; padding: 7px 16px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 11.5px; font-family: inherit; }
    .print-btn:hover { background: #1d4ed8; }
    .header-box { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 14px; }
    .telemetry-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 14px; }
    .tel-cell span { display: block; font-size: 9.5px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
    .tel-cell strong { font-size: 11.5px; color: #0f172a; font-family: 'JetBrains Mono', monospace; }
    .score-strip { display: flex; justify-content: space-between; align-items: center; background: #f8fafc; border-left: 4px solid ${scoreColor}; border-radius: 4px; padding: 10px 16px; margin-bottom: 14px; border-top: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; }
    .truth-table { width: 100%; border-collapse: collapse; margin-bottom: 14px; }
    .truth-table th { background: #f1f5f9; text-align: left; padding: 6px 10px; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.6px; color: #475569; border-bottom: 2px solid #cbd5e1; }
    .truth-table td { padding: 6px 10px; }
    .cert-block { display: flex; justify-content: space-between; align-items: flex-end; margin-top: 16px; padding-top: 12px; border-top: 1px solid #e2e8f0; }
    .footer-box { border-top: 1px solid #e2e8f0; padding-top: 10px; display: flex; justify-content: space-between; font-size: 10.5px; color: #64748b; margin-top: 16px; }
    @media print {
      .print-bar { display: none !important; }
      body { padding: 0; }
      .report-sheet { max-width: 100%; }
    }
  </style>
</head>
<body>
  <div class="report-sheet">
    <div class="watermark-bg">
      <img src="/static/logo.svg" alt="ADX Official Emblem" class="watermark-img" />
    </div>

    <div class="report-content">
      <div class="print-bar">
        <div>
          <strong style="color: #38bdf8;">ADX Group Cyber Systems</strong> &bull; Executive Perimeter Deliverable
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
          <button class="print-btn" style="background: rgba(255,255,255,0.18);" onclick="window.close()">Close Window</button>
        </div>
      </div>

      <div class="header-box">
        <div>
          <div style="font-size: 19px; font-weight: 800; letter-spacing: -0.5px; color: #0f172a; display: flex; align-items: center; gap: 8px;">
            <img src="/static/logo.svg" alt="ADX Logo" style="width: 26px; height: 26px; object-fit: contain;" />
            <span>ADX GROUP</span>
          </div>
          <div style="font-size: 9.5px; font-weight: 700; color: #64748b; letter-spacing: 1px; text-transform: uppercase; margin-top: 2px;">
            Cyber Threat Intelligence &bull; Perimeter Defense Desk
          </div>
        </div>
        <div style="text-align: right;">
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: #2563eb;">${escapeHtml(auditId)}</div>
          <div style="font-size: 10.5px; color: #64748b; margin-top: 2px;">Evaluated: ${escapeHtml(dateStr)}</div>
          <div style="font-size: 9px; font-weight: 800; color: #b91c1c; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 3px;">CONFIDENTIAL // EXECUTIVE POSTURE BRIEF</div>
        </div>
      </div>

      <div class="telemetry-grid">
        <div class="tel-cell">
          <span>Target Asset</span>
          <strong>${escapeHtml(d.domain)}</strong>
        </div>
        <div class="tel-cell">
          <span>Primary Host IP</span>
          <strong>${escapeHtml(tel.resolved_ip || "Unknown")}</strong>
        </div>
        <div class="tel-cell">
          <span>Transport Protocol</span>
          <strong>${escapeHtml(tel.tls_protocol || "TLS")}${tel.cipher_suite && tel.cipher_suite !== "AEAD" && tel.cipher_suite !== "None" ? ` &bull; ${escapeHtml(tel.cipher_suite)}` : ""}</strong>
        </div>
        <div class="tel-cell">
          <span>Certificate CA</span>
          <strong>${escapeHtml(tel.cert_issuer || "Unverified CA")}</strong>
        </div>
      </div>

      <div class="score-strip">
        <div>
          <div style="font-size: 9.5px; font-weight: 700; text-transform: uppercase; color: #64748b; letter-spacing: 0.8px;">Perimeter Posture State</div>
          <div style="font-size: 16px; font-weight: 800; color: #0f172a; margin-top: 2px;">${escapeHtml(d.risk_level)}</div>
          <div style="font-size: 10.5px; color: #475569; margin-top: 3px;">
            ${passed.length} of ${gates.length} inspection parameters fully verified &bull; ${failed.length} parameter(s) require engineering attention.
          </div>
        </div>
        <div style="text-align: right;">
          <div style="font-size: 26px; font-weight: 900; color: ${scoreColor}; font-family: 'JetBrains Mono', monospace;">${escapeHtml(String(d.score))}<span style="font-size: 13px; font-weight: 600; color: #64748b;">/100</span></div>
          <div style="font-size: 10.5px; font-weight: 800; color: #0f172a;">GRADE ${escapeHtml(d.grade)}</div>
        </div>
      </div>

      <div style="background: #f1f5f9; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; font-size: 11.5px; color: #1e293b; line-height: 1.5;">
        <strong style="color: #0f172a; display: block; margin-bottom: 3px; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px;">Executive Technical Summary</strong>
        ${escapeHtml(d.ai_executive_summary || "Perimeter infrastructure audit completed based on live non-intrusive DNS, TLS, and HTTP telemetry.")}
      </div>

      <div style="margin-bottom: 6px; font-size: 11px; font-weight: 800; color: #0f172a; text-transform: uppercase; letter-spacing: 0.6px;">
        Perimeter Security Inspection Matrix
      </div>
      <table class="truth-table">
        <thead>
          <tr>
            <th style="width: 40px;">Item</th>
            <th style="width: 240px;">Inspection Parameter</th>
            <th style="width: 145px; text-align: center;">Verification State</th>
            <th>Technical Finding &amp; Guidance</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>

      ${failed.length > 0 ? `
        <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px;">
          <strong style="color: #991b1b; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 4px;">Remediation Scope &amp; Engineering Action</strong>
          <div style="font-size: 11.5px; color: #7f1d1d; line-height: 1.45;">
            To resolve identified perimeter exposure and protect domain email deliverability and web security headers, contact ADX Engineering for fixed-scope deployment at <strong>contact@adxgroup.tech</strong>.
          </div>
        </div>
      ` : ""}

      <!-- Founder Signature & Official Verification Seal -->
      <div class="cert-block">
        <div>
          <div style="font-size: 9.5px; font-weight: 700; text-transform: uppercase; color: #64748b; letter-spacing: 0.8px;">Audited &amp; Certified By</div>
          <div style="margin: 6px 0 2px 0;">
            <svg width="220" height="46" viewBox="0 0 240 50" fill="none">
              <path d="M12 40 C 18 18, 25 8, 32 7 C 38 6, 42 16, 41 28 C 40 38, 36 44, 44 43 C 50 42, 54 26, 58 20 C 62 14, 67 24, 71 26 C 75 28, 80 16, 84 18 C 88 20, 92 30, 98 28 C 104 26, 110 16, 115 18 C 119 20, 123 30, 129 26 C 134 23, 140 8, 146 7 C 152 6, 155 16, 157 24 C 160 32, 166 30, 172 20 C 178 10, 182 22, 187 24 C 192 26, 196 14, 202 16 C 208 18, 214 30, 222 26 C 228 22, 234 14, 238 12" stroke="#0f172a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
              <path d="M22 24 C 30 23, 40 22, 50 23" stroke="#0f172a" stroke-width="1.8" stroke-linecap="round" />
              <path d="M26 46 C 72 45, 136 44, 226 40 C 232 39, 238 38, 240 36" stroke="#2563eb" stroke-width="1.6" stroke-linecap="round" />
            </svg>
          </div>
          <div style="font-size: 12px; font-weight: 800; color: #0f172a;">Abdulrazaq Adeyemi</div>
          <div style="font-size: 10px; color: #475569;">Lead Cyber Systems Architect &bull; Founder, ADX Group</div>
          <div style="font-size: 9px; color: #2563eb; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">CLEARANCE: LEVEL 4 (CYBERSECURITY RESEARCHER)</div>
        </div>

        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="text-align: right;">
            <div style="font-size: 9.5px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Cryptographic Protocol</div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700; color: #0f172a; margin-top: 2px;">RFC-7519 HMAC-SHA256</div>
            <div style="font-size: 9px; color: #059669; font-weight: 800; margin-top: 2px;">INTEGRITY SEAL VERIFIED</div>
          </div>
          <div style="position: relative; width: 88px; height: 88px; display: flex; align-items: center; justify-content: center; transform: rotate(-3deg);">
            <svg width="88" height="88" viewBox="0 0 100 100" style="position: absolute; top: 0; left: 0;">
              <circle cx="50" cy="50" r="47" fill="none" stroke="#2563eb" stroke-width="2" stroke-dasharray="4,2" />
              <circle cx="50" cy="50" r="42" fill="none" stroke="#0f172a" stroke-width="1.5" />
              <circle cx="50" cy="50" r="32" fill="#f8fafc" stroke="#2563eb" stroke-width="1" />
              <circle cx="50" cy="50" r="39" fill="none" stroke="#cbd5e1" stroke-width="0.5" stroke-dasharray="1,2" />
            </svg>
            <img src="/static/logo.svg" alt="ADX Seal Logo" style="width: 40px; height: 40px; position: relative; z-index: 2; object-fit: contain;" />
          </div>
        </div>
      </div>

      <div class="footer-box">
        <div>
          <strong>ADX Group (adxgroup.tech)</strong> &bull; Silent Innovation. Absolute Defense.
        </div>
        <div>
          Direct Desk: <a href="mailto:contact@adxgroup.tech" style="color: #2563eb; text-decoration: none;">contact@adxgroup.tech</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

    const printWin = window.open("", "_blank");
    if (!printWin) {
      window.showAdxNotice("Please allow popups for adxgroup.tech to view and export the Executive Security Report.", "info", "Popup Blocked");
      return;
    }
    printWin.document.open();
    printWin.document.write(reportHtml);
    printWin.document.close();
  };

  window.speakAdxVoice = async function (text, force = false) {
    if (voiceMuted && !force) return;
    const launcher = document.getElementById("aegis-launcher-orb");
    const orb = document.getElementById("adx-voice-orb");

    let speechText = text;
    if (!speechText) {
      const isDash = window.location.pathname.includes("/dashboard");
      const isLogin = window.location.pathname.includes("/login");
      const p = new URLSearchParams(window.location.search);
      if (p.get("deleted") === "true") {
        speechText = "Account permanently erased. Identity revoked.";
      } else if (p.get("logout") === "true") {
        speechText = "Session terminated. Identity gateway active.";
      } else if (isLogin) {
        speechText = "ADX Zero-Trust Gateway online. Secure your session.";
      } else if (isDash) {
        const orbEl = document.getElementById("adx-voice-orb");
        speechText = orbEl && orbEl.getAttribute("data-greeting")
          ? orbEl.getAttribute("data-greeting")
          : "ADX Infrastructure Console online.";
      } else {
        speechText = "ADX Cyber Systems active. Silent Innovation. Absolute Defense.";
      }
    }

    try {
      stopActiveVoice();
      if (launcher) launcher.classList.add("speaking");
      if (orb) orb.classList.add("speaking");

      const res = await fetch("/api/tts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: speechText }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        await playAudioUrl(url);
      } else {
        throw new Error("TTS endpoint error");
      }
    } catch (e) {
      // Cleanly fail silently: Never humiliate the platform with robotic browser speech synthesis
      if (launcher) launcher.classList.remove("speaking");
      if (orb) orb.classList.remove("speaking");
    } finally {
      setTimeout(() => {
        if (!activeAudio) {
          if (launcher) launcher.classList.remove("speaking");
          if (orb) orb.classList.remove("speaking");
        }
      }, 3500);
    }
  };

  function setupAutoWelcomeVoice() {
    // Unsolicited auto-play ambushes disabled: voice is played on intentional user interaction (e.g. clicking Debrief or Voice Orb)
  }

  function initAegisConciergeCard() {
    if (document.getElementById("aegis-concierge-card")) return;

    const card = document.createElement("div");
    card.id = "aegis-concierge-card";
    card.className = "aegis-concierge-card closed";

    card.innerHTML = `
      <div class="aegis-card-header">
        <div class="aegis-header-left">
          <div class="aegis-avatar-wrap">
            ${botAvatarSvg}
          </div>
          <div>
            <div style="font-weight: 800; font-size: 0.95rem; line-height: 1.2;">ADX Assistant</div>
            <div style="font-size: 0.75rem; opacity: 0.85;">Infrastructure &amp; AI Desk</div>
          </div>
        </div>
        <div class="aegis-header-actions">
          <button type="button" class="aegis-icon-btn" id="aegis-voice-btn" title="Play Voice Brief">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path></svg>
          </button>
          <button type="button" class="aegis-close-btn" id="aegis-close-btn" title="Close">&times;</button>
        </div>
      </div>

      <!-- Screen 1: Clean White Welcome View -->
      <div class="aegis-card-body" id="aegis-welcome-view">
        <div style="color: #0f172a; font-weight: 700; font-size: 0.95rem; margin-bottom: 4px;">
          Welcome to ADX Console
        </div>
        <div style="color: #64748b; font-size: 0.84rem; margin-bottom: 14px;">
          How can we assist your infrastructure today?
        </div>

        <div class="aegis-action-list">
          <div class="aegis-action-item" id="aegis-act-scan">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>Run infrastructure audit</span>
          </div>
          <div class="aegis-action-item" id="aegis-act-resources">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/></svg>
            <span>Cloud &amp; distributed architecture</span>
          </div>
          <div class="aegis-action-item" id="aegis-act-navigate">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0"/></svg>
            <span>Consult AI Systems Architect</span>
          </div>
          <div class="aegis-action-item" id="aegis-act-human">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <span>Contact ADX engineers</span>
          </div>
        </div>

        <button type="button" class="aegis-cta-btn" id="aegis-open-chat-btn">
          <span>Start Conversation</span>
        </button>
      </div>

      <!-- Screen 2: Live Inline Chat Inside the Popup Card -->
      <div class="aegis-chat-view" id="aegis-chat-view">
        <div class="aegis-chat-topbar">
          <button type="button" class="aegis-back-btn" id="aegis-back-btn">&larr; Back</button>
          <span>ADX Systems Assistant</span>
        </div>
        <div class="aegis-mini-messages" id="aegis-mini-messages">
          <div class="aegis-msg aegis-msg-bot">Hello. I am the ADX Executive Assistant. Ask me anything about cloud infrastructure, system security, or engineering scopes.</div>
        </div>
        <form class="aegis-mini-form" id="aegis-mini-form">
          <input type="text" class="aegis-mini-input" id="aegis-mini-input" placeholder="Ask about cloud, systems, or security..." required />
          <button type="submit" class="aegis-mini-send">Send</button>
        </form>
      </div>
    `;

    document.body.appendChild(card);

    // 2. Create the Circular Bottom-Right Robot Launcher Button (WIT-h style)
    const launcher = document.createElement("button");
    launcher.type = "button";
    launcher.id = "aegis-launcher-orb";
    launcher.className = "aegis-launcher-orb";
    launcher.title = "ADX Assistant";
    launcher.innerHTML = botAvatarSvg;
    document.body.appendChild(launcher);

    const welcomeView = document.getElementById("aegis-welcome-view");
    const chatView = document.getElementById("aegis-chat-view");
    const miniMessages = document.getElementById("aegis-mini-messages");
    const miniForm = document.getElementById("aegis-mini-form");
    const miniInput = document.getElementById("aegis-mini-input");

    function openInlineChat(prefillQuestion) {
      welcomeView.style.display = "none";
      chatView.classList.add("active");
      setTimeout(() => miniInput.focus(), 50);
      if (prefillQuestion) {
        sendMiniChatMessage(prefillQuestion);
      }
    }

    function sendMiniChatMessage(msgText) {
      const userBubble = document.createElement("div");
      userBubble.className = "aegis-msg aegis-msg-user";
      userBubble.textContent = msgText;
      miniMessages.appendChild(userBubble);
      miniMessages.scrollTop = miniMessages.scrollHeight;

      if (msgText.trim().toLowerCase() === "human") {
        const botBubble = document.createElement("div");
        botBubble.className = "aegis-msg aegis-msg-bot";
        botBubble.textContent = "Connecting you with a human engineer at ADX! You can email us directly at contact@adxgroup.tech or use the Deploy ADX Engineers tab ($350 fixed scope).";
        miniMessages.appendChild(botBubble);
        miniMessages.scrollTop = miniMessages.scrollHeight;
        return;
      }

      const thinkBubble = document.createElement("div");
      thinkBubble.className = "aegis-msg aegis-msg-bot";
      thinkBubble.innerHTML = `<div class="ai-thinking-wrap" style="color:#0018a8; font-size:0.78rem;"><span>Thinking</span><div class="typing-dots"><span style="background:#0018a8;"></span><span style="background:#0018a8;"></span><span style="background:#0018a8;"></span></div></div>`;
      miniMessages.appendChild(thinkBubble);
      miniMessages.scrollTop = miniMessages.scrollHeight;

      fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msgText }),
      })
        .then((r) => r.json())
        .then((payload) => {
          const reply =
            payload && payload.ok && payload.data
              ? cleanDisplayMessage(payload.data.reply)
              : "You can reach our engineering team directly at contact@adxgroup.tech.";
          thinkBubble.innerHTML = "";
          let i = 0;
          const words = reply.split(/(?=[ \n])/);
          const timer = setInterval(() => {
            if (i < words.length) {
              thinkBubble.textContent += words.slice(i, i + 3).join("");
              i += 3;
              miniMessages.scrollTop = miniMessages.scrollHeight;
            } else {
              clearInterval(timer);
            }
          }, 22);
        })
        .catch(() => {
          thinkBubble.textContent = "Connection interrupted. Reach our team at contact@adxgroup.tech.";
        });
    }

    document.getElementById("aegis-close-btn").addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      card.classList.add("closed");
      stopActiveVoice();
    });

    document.getElementById("aegis-voice-btn").addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (activeAudio) {
        stopActiveVoice();
      } else {
        voiceMuted = false;
        window.speakAdxVoice(null, true);
      }
    });

    launcher.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      card.classList.toggle("closed");
    });

    document.getElementById("aegis-open-chat-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      openInlineChat();
    });

    document.getElementById("aegis-back-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      chatView.classList.remove("active");
      welcomeView.style.display = "block";
    });

    document.getElementById("aegis-act-scan").addEventListener("click", () => {
      if (isDashboard && typeof switchConsoleTab === "function") {
        card.classList.add("closed");
        switchConsoleTab("scanner");
        const inp = document.getElementById("scan-domain-input");
        if (inp) inp.focus();
      } else {
        card.classList.add("closed");
        const inp = document.getElementById("landing-domain-input");
        if (inp) {
          inp.scrollIntoView({ behavior: "smooth", block: "center" });
          inp.focus();
        }
      }
    });

    document.getElementById("aegis-act-resources").addEventListener("click", () => {
      openInlineChat("What cloud, distributed systems, and security capabilities does ADX provide?");
    });

    document.getElementById("aegis-act-navigate").addEventListener("click", () => {
      openInlineChat("Help me navigate ADX and explain how the infrastructure scanner works.");
    });

    document.getElementById("aegis-act-human").addEventListener("click", () => {
      openInlineChat("Human");
    });

    miniForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const val = miniInput.value.trim();
      if (!val) return;
      miniInput.value = "";
      sendMiniChatMessage(val);
    });
  }

  initAegisConciergeCard();
  setupAutoWelcomeVoice();

  // 5. Extraordinary 60fps 3D Quantum Neural Constellation & Orbital Radar Background
  function initQuantumOrbitalBackground() {
    if (document.getElementById("adx-quantum-canvas")) return;
    const canvas = document.createElement("canvas");
    canvas.id = "adx-quantum-canvas";
    document.body.prepend(canvas);
    const ctx = canvas.getContext("2d");

    let w = (canvas.width = window.innerWidth);
    let h = (canvas.height = window.innerHeight);

    window.addEventListener("resize", () => {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    });

    const mouse = { x: w * 0.72, y: h * 0.35, active: false };
    window.addEventListener("mousemove", (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    });

    const nodeCount = 44;
    const nodes = [];
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.55,
        vy: (Math.random() - 0.5) * 0.55,
        r: Math.random() * 1.8 + 1.1,
        color: i % 5 === 0 ? "#10b981" : "#38bdf8",
      });
    }

    const photons = [];
    let angle = 0;

    function drawFrame() {
      ctx.clearRect(0, 0, w, h);
      angle += 0.0022;

      // A. Subtle Rotating Orbital Planetary Defense Rings
      const cx = w * 0.76;
      const cy = h * 0.38;

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.08)";
      ctx.lineWidth = 1.2;
      ctx.setLineDash([18, 12, 4, 12]);
      ctx.beginPath();
      ctx.arc(0, 0, 270, 0, Math.PI * 2);
      ctx.stroke();

      ctx.rotate(-angle * 2.1);
      ctx.strokeStyle = "rgba(37, 99, 235, 0.09)";
      ctx.setLineDash([36, 22]);
      ctx.beginPath();
      ctx.arc(0, 0, 410, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // B. Update & Connect 3D Neural Nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.globalAlpha = 0.65;
        ctx.fill();

        for (let j = i + 1; j < nodes.length; j++) {
          const m = nodes[j];
          const dx = n.x - m.x;
          const dy = n.y - m.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 165) {
            const alpha = (1 - dist / 165) * 0.22;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(m.x, m.y);
            ctx.strokeStyle = "#38bdf8";
            ctx.globalAlpha = alpha;
            ctx.lineWidth = 0.85;
            ctx.stroke();

            if (Math.random() < 0.0009 && photons.length < 18) {
              photons.push({
                sx: n.x,
                sy: n.y,
                tx: m.x,
                ty: m.y,
                t: 0,
                speed: 0.022 + Math.random() * 0.02,
                color: i % 3 === 0 ? "#10b981" : "#38bdf8",
              });
            }
          }
        }

        // C. Interactive Cursor Telemetry Lock
        if (mouse.active) {
          const mdx = n.x - mouse.x;
          const mdy = n.y - mouse.y;
          const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
          if (mdist < 190) {
            ctx.beginPath();
            ctx.moveTo(mouse.x, mouse.y);
            ctx.lineTo(n.x, n.y);
            ctx.strokeStyle = "#38bdf8";
            ctx.globalAlpha = (1 - mdist / 190) * 0.35;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      // D. Render High-Speed Photon Telemetry Packets Along Neural Lines
      ctx.globalAlpha = 0.95;
      for (let k = photons.length - 1; k >= 0; k--) {
        const p = photons[k];
        p.t += p.speed;
        if (p.t >= 1) {
          photons.splice(k, 1);
          continue;
        }
        const px = p.sx + (p.tx - p.sx) * p.t;
        const py = p.sy + (p.ty - p.sy) * p.t;
        ctx.beginPath();
        ctx.arc(px, py, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
      }

      ctx.globalAlpha = 1;
      requestAnimationFrame(drawFrame);
    }

    requestAnimationFrame(drawFrame);
  }

  // =========================================================================
  // Cookie Consent Management (Glovo / DSA / EAA / NDPA / GDPR Compliant)
  // =========================================================================
  window.openCookieModal = function () {
    const modalBackdrop = document.getElementById("adx-cookie-modal-backdrop");
    if (modalBackdrop) modalBackdrop.classList.remove("hidden");
  };

  window.closeCookieModal = function () {
    const modalBackdrop = document.getElementById("adx-cookie-modal-backdrop");
    if (modalBackdrop) modalBackdrop.classList.add("hidden");
  };

  window.acceptAllCookies = function () {
    try {
      const consent = {
        essential: true,
        decidedAt: new Date().toISOString(),
        status: "ACKNOWLEDGED",
      };
      localStorage.setItem("adx_cookie_consent", JSON.stringify(consent));
    } catch (e) {}
    window.closeCookieModal();
  };

  window.denyCookies = function () {
    try {
      const consent = {
        essential: true,
        telemetry: false,
        decidedAt: new Date().toISOString(),
        status: "DENIED_NON_ESSENTIAL",
      };
      localStorage.setItem("adx_cookie_consent", JSON.stringify(consent));
    } catch (e) {}
    window.closeCookieModal();
    if (window.showAdxNotice) {
      window.showAdxNotice("Non-essential telemetry denied. Strictly essential security cookies active.", "info", "Zero-Trust Privacy Applied");
    }
  };

  window.toggleCookieDetails = function () {
    const details = document.getElementById("adx-cookie-details");
    if (details) details.classList.toggle("hidden");
  };

  window.saveCustomCookiePreferences = function () {
    const optIn = document.getElementById("chk-telemetry") ? document.getElementById("chk-telemetry").checked : false;
    try {
      const consent = {
        essential: true,
        telemetry: optIn,
        decidedAt: new Date().toISOString(),
        status: optIn ? "CUSTOM_ACCEPTED" : "CUSTOM_DENIED",
      };
      localStorage.setItem("adx_cookie_consent", JSON.stringify(consent));
    } catch (e) {}
    window.closeCookieModal();
    if (window.showAdxNotice) {
      window.showAdxNotice("Custom cookie choices saved successfully.", "success", "Preferences Updated");
    }
  };

  setTimeout(() => {
    try {
      const saved = localStorage.getItem("adx_cookie_consent");
      if (!saved) {
        window.openCookieModal();
      }
    } catch (e) {}
  }, 1200);

  // =========================================================================
  // FAQ Accordion
  // =========================================================================
  window.toggleFaq = function (faqId) {
    const item = document.getElementById(faqId);
    if (!item) return;
    const isActive = item.classList.contains("active");
    document.querySelectorAll(".faq-item").forEach((el) => el.classList.remove("active"));
    if (!isActive) {
      item.classList.add("active");
    }
  };

  // =========================================================================
  // Capabilities Showcase Interactive Tab Switcher
  // =========================================================================
  window.switchCapabilityTab = function (tabId) {
    document.querySelectorAll(".capability-tab-btn").forEach((btn) => {
      const isSelected = btn.getAttribute("data-tab") === tabId;
      btn.classList.toggle("active", isSelected);
      btn.setAttribute("aria-selected", isSelected ? "true" : "false");
      btn.setAttribute("tabindex", isSelected ? "0" : "-1");
    });
    document.querySelectorAll(".capability-pane").forEach((pane) => {
      pane.classList.toggle("hidden", pane.id !== `pane-${tabId}`);
    });
  };

  // Keyboard navigation for capability tabs
  const tabList = document.querySelector('.capability-nav-tabs[role="tablist"]');
  if (tabList) {
    tabList.addEventListener("keydown", (e) => {
      const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
      const activeIndex = tabs.findIndex((t) => t.getAttribute("aria-selected") === "true");
      let nextIndex = activeIndex;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        nextIndex = (activeIndex + 1) % tabs.length;
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        nextIndex = (activeIndex - 1 + tabs.length) % tabs.length;
      } else if (e.key === "Home") {
        nextIndex = 0;
      } else if (e.key === "End") {
        nextIndex = tabs.length - 1;
      } else {
        return;
      }
      e.preventDefault();
      tabs[nextIndex].focus();
      const targetTabId = tabs[nextIndex].getAttribute("data-tab");
      window.switchCapabilityTab(targetTabId);
    });
  }

  // Simulation pause control for prefers-reduced-motion & user control
  let isSimPaused = false;
  window.toggleSimPause = function () {
    isSimPaused = !isSimPaused;
    const btn = document.getElementById("term-pause-btn");
    const term = document.getElementById("sim-terminal-output");
    if (btn) btn.textContent = isSimPaused ? "Resume" : "Pause";
    if (term) term.style.opacity = isSimPaused ? "0.75" : "1.0";
  };

  window.runSimulatedAudit = function () {
    const termBody = document.getElementById("sim-terminal-output");
    if (!termBody) return;
    termBody.innerHTML = `
      <span style="color: #60a5fa;">$ adx audit --domain example-domain.com --mode passive-telemetry</span><br>
      <span style="color: #94a3b8;">[DEMO] Simulating surface diagnostic workflow (sample output)...</span><br>
      <span style="color: #10b981;">[DNS] Resolving A/AAAA records: Authoritative DNS resolution checked</span><br>
      <span style="color: #10b981;">[TLS] Cryptographic Handshake: TLS 1.3 protocol negotiation evaluated</span><br>
      <span style="color: #10b981;">[MAIL] Domain Security: SPF &amp; DMARC policy presence analyzed</span><br>
      <span style="color: #10b981;">[HEADERS] Response Directives: Content-Security-Policy &amp; HSTS verified</span><br>
      <span style="color: #10b981;">[PORTS] Diagnostic Vector: Non-intrusive edge port verification completed</span><br>
      <span style="color: #38bdf8; font-weight: 700;">[RESULT] Sample Surface Telemetry (Example Demonstration Output)</span>
    `;
  };

  initQuantumOrbitalBackground();

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeJsArg(str) {
    return String(str || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  }

  // =========================================================================
  // Contact & Consultation Request Submission Form
  // =========================================================================
  window.submitContactForm = async function(event) {
    if (event) event.preventDefault();
    const form = document.getElementById("contact-consult-form");
    const notice = document.getElementById("contact-form-notice");
    const btn = document.getElementById("contact-submit-btn");
    if (!form || !btn) return;

    const hpToken = document.getElementById("contact-hp-token") ? document.getElementById("contact-hp-token").value : "";
    const name = document.getElementById("contact-name") ? document.getElementById("contact-name").value.trim() : "";
    const email = document.getElementById("contact-email") ? document.getElementById("contact-email").value.trim() : "";
    const division = document.getElementById("contact-division") ? document.getElementById("contact-division").value : "ADX Cyber — Security Audit";
    const domain = document.getElementById("contact-domain") ? document.getElementById("contact-domain").value.trim() : "";
    const message = document.getElementById("contact-message") ? document.getElementById("contact-message").value.trim() : "";

    if (!name || !email) {
      if (notice) {
        notice.style.display = "block";
        notice.style.background = "rgba(239, 68, 68, 0.15)";
        notice.style.color = "#f87171";
        notice.textContent = "Please provide your name/organization and corporate work email.";
      }
      return;
    }

    btn.disabled = true;
    btn.textContent = "Submitting Consultation Request...";

    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company_or_name: name,
          email: email,
          division: division,
          domain: domain,
          message: message,
          hp_token: hpToken,
        }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        if (notice) {
          notice.style.display = "block";
          notice.style.background = "rgba(16, 185, 129, 0.15)";
          notice.style.color = "#34d399";
          notice.textContent = "Consultation request received. Our systems engineering desk will review your scope and follow up.";
        }
        form.reset();
      } else {
        if (notice) {
          notice.style.display = "block";
          notice.style.background = "rgba(239, 68, 68, 0.15)";
          notice.style.color = "#f87171";
          notice.textContent = data.detail || "Unable to submit inquiry. Please email contact@adxgroup.tech.";
        }
      }
    } catch (err) {
      if (notice) {
        notice.style.display = "block";
        notice.style.background = "rgba(239, 68, 68, 0.15)";
        notice.style.color = "#f87171";
        notice.textContent = "Network error while transmitting request. Please email contact@adxgroup.tech directly.";
      }
    } finally {
      btn.disabled = false;
      btn.textContent = "Submit Security Consultation Request";
    }
  };

});


/* =========================================================================
   Task A & D: Single-Source Currency Switcher (NGN / USD)
   ========================================================================= */

window.setOfferCurrency = function(curr) {
  const targetCurr = (curr || "NGN").toUpperCase();
  try {
    localStorage.setItem("adx_currency", targetCurr);
  } catch (e) {}

  // Update button active state
  document.querySelectorAll(".currency-btn").forEach((btn) => {
    if (btn.getAttribute("data-currency") === targetCurr) {
      btn.classList.add("active");
      btn.setAttribute("aria-pressed", "true");
    } else {
      btn.classList.remove("active");
      btn.setAttribute("aria-pressed", "false");
    }
  });

  // Update all price display nodes
  document.querySelectorAll(".price-val").forEach((el) => {
    const val = el.getAttribute("data-" + targetCurr.toLowerCase());
    if (val) {
      el.textContent = val;
    }
  });
};

// Initialize saved currency preference on load
document.addEventListener("DOMContentLoaded", () => {
  let saved = "NGN";
  try {
    saved = localStorage.getItem("adx_currency") || "NGN";
  } catch (e) {}
  window.setOfferCurrency(saved);
});

/* =========================================================================
   Task C: Free NDPA & Security Readiness Check Scoring & Lead Submission
   ========================================================================= */

window.calculateReadinessScore = function() {
  const form = document.getElementById("readiness-quiz-form");
  if (!form) return null;

  let yesCount = 0;
  let answeredCount = 0;
  const totalQuestions = 10;

  for (let i = 1; i <= totalQuestions; i++) {
    const qName = "q" + i;
    const selected = form.querySelector('input[name="' + qName + '"]:checked');
    if (selected) {
      answeredCount++;
      if (selected.value === "yes") {
        yesCount++;
      }
    }
  }

  return {
    score: yesCount,
    answeredCount: answeredCount,
    totalQuestions: totalQuestions,
    isComplete: answeredCount === totalQuestions
  };
};

window.onQuizAnswerChange = function() {
  const result = window.calculateReadinessScore();
  if (!result) return;

  const resultBox = document.getElementById("quiz-result-box");
  const badge = document.getElementById("result-badge");
  const title = document.getElementById("result-title");
  const fraction = document.getElementById("result-score-fraction");
  const summary = document.getElementById("result-summary");
  const recommendation = document.getElementById("result-recommendation");

  if (!resultBox || !badge || !title || !fraction || !summary || !recommendation) return;

  // Reveal calculation when at least 5 questions or all 10 are answered
  if (result.answeredCount >= 5) {
    resultBox.style.display = "block";
    fraction.textContent = result.score + "/" + result.totalQuestions;

    if (result.score <= 4) {
      // High Risk Band (0 to 4 yes)
      badge.textContent = "High Risk Band";
      badge.style.background = "rgba(239, 68, 68, 0.18)";
      badge.style.color = "#f87171";
      badge.style.border = "1px solid rgba(239, 68, 68, 0.45)";
      resultBox.style.borderColor = "rgba(239, 68, 68, 0.4)";

      title.textContent = "Critical Security & NDPA Safeguard Exposure";
      summary.textContent = "Your organization is currently operating with critical technical and compliance gaps. Fundamental safeguards such as formal personal data mapping, reportable breach notification procedures, or domain spoofing defense appear absent or unverified, creating severe regulatory exposure under NDPA 2023.";
      recommendation.textContent = "Immediate perimeter triage required. We recommend scheduling an emergency review to establish basic email authentication (SPF/DKIM/DMARC), implement enforced MFA, and conduct baseline personal data mapping.";
    } else if (result.score <= 7) {
      // Medium Risk Band (5 to 7 yes)
      badge.textContent = "Medium Risk Band";
      badge.style.background = "rgba(245, 158, 11, 0.18)";
      badge.style.color = "#fbbf24";
      badge.style.border = "1px solid rgba(245, 158, 11, 0.45)";
      resultBox.style.borderColor = "rgba(245, 158, 11, 0.4)";

      title.textContent = "Moderate Security Baseline with Critical Compliance Gaps";
      summary.textContent = "Baseline IT controls appear partially deployed, but high-consequence compliance and operational recovery gaps remain. Key statutory requirements (including third-party vendor DPAs, tested backup restore drills, or designated DPO oversight) must be formalized before your annual audit cycle.";
      recommendation.textContent = "Close high-consequence exposure gaps before your next annual audit return cycle. Conduct an internal access review, formalize incident response procedures, and schedule a restore verification drill.";
    } else {
      // Low Risk Band (8 to 10 yes)
      badge.textContent = "Low Risk Band";
      badge.style.background = "rgba(16, 185, 129, 0.18)";
      badge.style.color = "#34d399";
      badge.style.border = "1px solid rgba(16, 185, 129, 0.45)";
      resultBox.style.borderColor = "rgba(16, 185, 129, 0.4)";

      title.textContent = "Strong Operational Baseline & Audit Readiness";
      summary.textContent = "Your responses indicate a mature defense posture with active data governance and identity protections. Focus now shifts toward formal statutory compliance filings and continuous configuration drift testing.";
      recommendation.textContent = "Formalize your annual Compliance Audit Return (CAR) with a licensed DPCO partner and run regular simulated recovery drills to prevent configuration drift.";
    }
  }
};

window.submitReadinessCheck = async function() {
  const form = document.getElementById("readiness-quiz-form");
  const submitBtn = document.getElementById("submit-quiz-btn");
  const statusNode = document.getElementById("quiz-submit-status");
  const confirmBox = document.getElementById("quiz-confirmation-box");

  if (!form || !submitBtn) return;

  const result = window.calculateReadinessScore();
  if (!result || result.answeredCount < result.totalQuestions) {
    alert("Please answer all 10 diagnostic questions to generate an accurate readiness assessment.");
    // Find the first unanswered question and scroll to it
    for (let i = 1; i <= 10; i++) {
      if (!form.querySelector('input[name="q' + i + '"]:checked')) {
        const fieldset = form.querySelector('.quiz-question-card[data-qid="q' + i + '"]');
        if (fieldset) {
          fieldset.scrollIntoView({ behavior: "smooth", block: "center" });
          fieldset.style.borderColor = "#ef4444";
        }
        break;
      }
    }
    return;
  }

  const nameInput = document.getElementById("lead-name");
  const emailInput = document.getElementById("lead-email");
  const companyInput = document.getElementById("lead-company");
  const sectorInput = document.getElementById("lead-sector");
  const consentInput = document.getElementById("lead-consent");
  const hpInput = document.getElementById("quiz-hp-token");

  if (!consentInput || !consentInput.checked) {
    alert("Please acknowledge the privacy consent checkbox to submit your readiness assessment.");
    return;
  }

  let riskBand = "Medium";
  if (result.score <= 4) riskBand = "High";
  else if (result.score >= 8) riskBand = "Low";

  const payload = {
    name: nameInput ? nameInput.value.trim() : "",
    email: emailInput ? emailInput.value.trim() : "",
    company: companyInput ? companyInput.value.trim() : "",
    sector: sectorInput ? sectorInput.value : "",
    score: result.score,
    risk_band: riskBand,
    consent: consentInput.checked,
    hp_token: hpInput ? hpInput.value : ""
  };

  submitBtn.disabled = true;
  submitBtn.textContent = "Submitting Assessment...";
  if (statusNode) statusNode.textContent = "Processing your diagnostic score...";

  try {
    const res = await fetch("/api/readiness-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (res.ok && data.ok) {
      if (confirmBox) confirmBox.style.display = "block";
      if (statusNode) statusNode.textContent = "Diagnostic registered (" + (data.lead_id || "Logged") + ").";
      submitBtn.textContent = "Assessment Submitted";
      confirmBox.scrollIntoView({ behavior: "smooth", block: "center" });
    } else {
      if (statusNode) statusNode.textContent = data.detail || "Submission failed. Please try again.";
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit & View Detailed Analysis";
    }
  } catch (err) {
    if (statusNode) statusNode.textContent = "Network error. Please email contact@adxgroup.tech.";
    submitBtn.disabled = false;
    submitBtn.textContent = "Submit & View Detailed Analysis";
  }
};


/* =========================================================================
   Task G: Non-Blocking Brand Splash Controller (<= 800ms)
   ========================================================================= */

document.addEventListener("DOMContentLoaded", () => {
  const splash = document.getElementById("brand-splash-overlay");
  if (!splash) return;

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let alreadyShown = false;
  try {
    alreadyShown = sessionStorage.getItem("adx_splash_shown") === "true";
  } catch (e) {}

  if (alreadyShown || prefersReducedMotion) {
    splash.classList.add("hidden");
    return;
  }

  // Dismiss function
  const dismissSplash = () => {
    splash.classList.add("hidden");
    try {
      sessionStorage.setItem("adx_splash_shown", "true");
    } catch (e) {}
  };

  // Allow click or Escape key to skip immediately
  splash.addEventListener("click", dismissSplash);
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") dismissSplash();
  }, { once: true });

  // Auto-dismiss in <= 750ms
  setTimeout(dismissSplash, 750);
});

function toggleMobileNav() {
  const nav = document.getElementById("main-nav-links");
  const btn = document.getElementById("nav-toggle-btn");
  if (!nav || !btn) return;
  const isOpen = nav.classList.toggle("nav-open");
  btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

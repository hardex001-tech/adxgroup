document.addEventListener("DOMContentLoaded", () => {
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

      scanBtn.disabled = true;
      scanBtn.textContent = "Inspecting Host IP, TLS & 2026 CVEs...";

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        });

        if (res.status === 401) {
          window.location.href = `/login?domain=${encodeURIComponent(domain)}`;
          return;
        }

        const payload = await res.json();
        if (!res.ok || !payload.ok) {
          alert(payload.detail || "Could not complete scan. Verify the domain name.");
          return;
        }

        const data = payload.data;
        const tel = data.telemetry || {};

        resultsBox.classList.remove("hidden");
        domainTitle.textContent = `${data.domain} | Live Telemetry & 2026 CVE Audit (${data.timestamp})`;
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
            scoreRingCircle.style.stroke = "#38bdf8";
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
              <strong>${escapeHtml(tel.tls_protocol || "None")} (${escapeHtml(tel.cipher_suite || "N/A")})</strong>
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
              <strong style="color: var(--accent-cyan);">6-Gate Surface + 2026 CVE</strong>
            </div>
          `;
        }

        if (cveReportMatrix && Array.isArray(data.cve_2026_report)) {
          const mitigatedCount = data.cve_2026_report.filter((c) => c.passed).length;
          const openCount = data.cve_2026_report.length - mitigatedCount;
          if (cveSummaryBadge) {
            cveSummaryBadge.textContent = `${mitigatedCount} MITIGATED | ${openCount} OPEN / UNVERIFIED 2026 CVEs`;
          }

          cveReportMatrix.innerHTML = data.cve_2026_report
            .map((c) => {
              let statusClass = "badge-false";
              if (c.passed) {
                statusClass = "badge-true";
              } else if (c.gate_id === "GATE-06") {
                statusClass = "badge-warn";
              }
              return `
                <div class="cve-report-card">
                  <div class="cve-card-top">
                    <span class="cve-id-pill">${escapeHtml(c.cve_id)}</span>
                    <span class="cvss-pill">CVSS ${escapeHtml(c.cvss)}</span>
                  </div>
                  <div style="font-weight: 700; font-size: 0.86rem; color: var(--text-main); margin-bottom: 4px;">
                    ${escapeHtml(c.title)}
                  </div>
                  <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted); margin-bottom: 8px;">
                    Target Surface: ${escapeHtml(c.surface)}
                  </div>
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted);">${escapeHtml(c.gate_id)}</span>
                    <span class="${statusClass}" style="padding: 2px 8px; font-size: 0.68rem;">${escapeHtml(c.status)}</span>
                  </div>
                </div>
              `;
            })
            .join("");
        }

        gatesTableBody.innerHTML = "";
        data.gates.forEach((g) => {
          const tr = document.createElement("tr");
          let badgeClass = "badge-false";
          if (g.state === true) {
            badgeClass = "badge-true";
          } else if (g.gate_id === "GATE-06") {
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
            const safeGate = escapeJsArg(g.gate_id);
            const safeVector = escapeJsArg(g.vector);
            const safeCve = escapeJsArg(g.cve_ref || "2026-CVE");

            actionHtml = `
              <div class="locked-patch-bar">
                <div>
                  <strong style="color: var(--text-main); display: block; margin-bottom: 3px;">
                    🔒 Remediation Patch &amp; Verification Locked (ADX Engineering)
                  </strong>
                  ${clientNote}
                </div>
                <button
                  type="button"
                  class="btn btn-primary"
                  style="padding: 8px 14px; font-size: 0.78rem; white-space: nowrap;"
                  onclick="requestPatchForGate('${safeDomain}', '${safeGate}', '${safeVector}', '${safeCve}')"
                >
                  Deploy Fix with ADX ($350) &rarr;
                </button>
              </div>
            `;
          }

          tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-weight: 700;">${escapeHtml(g.gate_id)}</td>
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

        if (window.speakAdxVoice) {
          window.speakAdxVoice(
            `Diagnostic complete for ${data.domain}. Surface security posture scored ${data.score} out of 100, Grade ${data.grade}.`
          );
        }
      } catch (err) {
        alert("Network error while running diagnostic scan.");
      } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Run 6-Gate CVE Audit";
      }
    });
  }

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

  // 4. AEGIS — ADX Executive Neural Voice Concierge (Speaker Welcome & Alerts)
  const voiceOrb = document.getElementById("adx-voice-orb");
  const voiceLabel = document.getElementById("adx-voice-label");
  let voiceMuted = false;
  let hasWelcomed = false;

  function pickBestNeuralVoice() {
    if (!("speechSynthesis" in window)) return null;
    const voices = window.speechSynthesis.getVoices() || [];
    const preferred = [
      "Microsoft Aria Online (Natural)",
      "Microsoft Sonia Online (Natural)",
      "Microsoft Guy Online (Natural)",
      "Microsoft Ryan Online (Natural)",
      "Google UK English Female",
      "Google US English",
    ];
    for (const p of preferred) {
      const match = voices.find((v) => v.name.includes(p));
      if (match) return match;
    }
    return voices.find((v) => v.lang && v.lang.startsWith("en")) || voices[0] || null;
  }

  window.speakAdxVoice = function (text, force = false) {
    if (!("speechSynthesis" in window)) return;
    if (voiceMuted && !force) return;

    try {
      window.speechSynthesis.cancel();
      const utter = new SpeechSynthesisUtterance(text);
      const bestVoice = pickBestNeuralVoice();
      if (bestVoice) utter.voice = bestVoice;
      utter.rate = 1.02;
      utter.pitch = 1.0;

      utter.onstart = () => {
        if (voiceOrb) voiceOrb.classList.add("speaking");
        if (voiceLabel) voiceLabel.textContent = "AEGIS Speaking...";
      };
      utter.onend = () => {
        if (voiceOrb) voiceOrb.classList.remove("speaking");
        if (voiceLabel) voiceLabel.textContent = "AEGIS Voice Brief";
      };
      utter.onerror = () => {
        if (voiceOrb) voiceOrb.classList.remove("speaking");
        if (voiceLabel) voiceLabel.textContent = "AEGIS Voice Brief";
      };

      window.speechSynthesis.speak(utter);
    } catch (e) {
      // Ignore browser autoplay block until first interaction
    }
  };

  function getWelcomeGreeting() {
    if (voiceOrb && voiceOrb.dataset.greeting) {
      return voiceOrb.dataset.greeting;
    }
    return "Welcome to A D X Group. Silent Innovation. Absolute Defense. Enter your company domain to run a live 2026 C V E security diagnostic.";
  }

  function triggerAutoWelcome() {
    if (hasWelcomed) return;
    hasWelcomed = true;
    window.speakAdxVoice(getWelcomeGreeting(), true);
  }

  if ("speechSynthesis" in window) {
    window.speechSynthesis.onvoiceschanged = () => {
      pickBestNeuralVoice();
    };
    // Attempt immediate welcome; if browser waits for first user click, fire on first click
    setTimeout(() => {
      if (!window.speechSynthesis.speaking && !hasWelcomed) {
        window.speakAdxVoice(getWelcomeGreeting(), true);
        setTimeout(() => {
          if (window.speechSynthesis.speaking) {
            hasWelcomed = true;
          }
        }, 250);
      }
    }, 600);

    const onFirstInteract = (e) => {
      if (voiceOrb && voiceOrb.contains(e.target)) return;
      if (!hasWelcomed) {
        triggerAutoWelcome();
      }
      document.removeEventListener("click", onFirstInteract);
    };
    document.addEventListener("click", onFirstInteract);
  }

  if (voiceOrb) {
    voiceOrb.addEventListener("click", () => {
      if (!("speechSynthesis" in window)) return;
      if (window.speechSynthesis.speaking) {
        window.speechSynthesis.cancel();
        voiceOrb.classList.remove("speaking");
        if (voiceLabel) voiceLabel.textContent = "AEGIS Voice Muted";
        voiceMuted = true;
      } else {
        voiceMuted = false;
        hasWelcomed = true;
        window.speakAdxVoice(getWelcomeGreeting(), true);
      }
    });
  }

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
});

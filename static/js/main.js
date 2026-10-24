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

  // 4. ADX's BFF (AEGIS) — WIT-h Style White & Royal-Blue Floating Assistant + Studio Neural AI Voice
  const oldVoiceOrb = document.getElementById("adx-voice-orb");
  if (oldVoiceOrb) {
    oldVoiceOrb.style.display = "none";
  }

  let voiceMuted = false;
  let hasWelcomed = false;
  let activeAudio = null;

  const botAvatarSvg = `
    <svg width="28" height="28" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="botHeadGrad" cx="35%" cy="25%" r="70%">
          <stop offset="0%" stop-color="#93c5fd"/>
          <stop offset="55%" stop-color="#2563eb"/>
          <stop offset="100%" stop-color="#1e3a8a"/>
        </radialGradient>
      </defs>
      <line x1="32" y1="6" x2="32" y2="14" stroke="#93c5fd" stroke-width="3" stroke-linecap="round"/>
      <circle cx="32" cy="5" r="3.5" fill="#38bdf8"/>
      <rect x="12" y="14" width="40" height="34" rx="16" fill="url(#botHeadGrad)" stroke="#bfdbfe" stroke-width="2"/>
      <rect x="17" y="21" width="30" height="16" rx="8" fill="#091540"/>
      <circle cx="25.5" cy="29" r="3.2" fill="#38bdf8"/>
      <circle cx="38.5" cy="29" r="3.2" fill="#38bdf8"/>
      <path d="M26 41C28 43 36 43 38 41" stroke="#e0f2fe" stroke-width="2.5" stroke-linecap="round"/>
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

  window.speakAdxVoice = async function (text, force = false) {
    if (voiceMuted && !force) return;
    if (!text) {
      const isDash = window.location.pathname.includes("/dashboard");
      const welcomeUrl = isDash
        ? "/static/audio/welcome_console.mp3?v=2026.18"
        : "/static/audio/welcome_home.mp3?v=2026.18";
      playAudioUrl(welcomeUrl).catch(() => {
        const launcher = document.getElementById("aegis-launcher-orb");
        if (launcher) launcher.classList.remove("speaking");
      });
      return;
    }
    try {
      stopActiveVoice();
      const res = await fetch("/api/tts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      playAudioUrl(url).catch(() => {});
    } catch (e) {}
  };

  function setupAutoWelcomeVoice() {
    const isDash = window.location.pathname.includes("/dashboard");
    const welcomeUrl = isDash
      ? "/static/audio/welcome_console.mp3?v=2026.18"
      : "/static/audio/welcome_home.mp3?v=2026.18";

    const bindFallbackUnlock = () => {
      const unlockHandler = (e) => {
        const closeBtn = document.getElementById("aegis-close-btn");
        if (closeBtn && closeBtn.contains(e.target)) {
          cleanupUnlock();
          return;
        }
        if (!hasWelcomed && !voiceMuted) {
          hasWelcomed = true;
          playAudioUrl(welcomeUrl).catch(() => {});
        }
        cleanupUnlock();
      };
      const cleanupUnlock = () => {
        document.removeEventListener("click", unlockHandler);
        document.removeEventListener("keydown", unlockHandler);
        document.removeEventListener("touchstart", unlockHandler);
      };
      document.addEventListener("click", unlockHandler);
      document.addEventListener("keydown", unlockHandler);
      document.addEventListener("touchstart", unlockHandler);
    };

    // Attempt immediate playback on login/load; if browser requires gesture first, unlock on first click
    playAudioUrl(welcomeUrl).catch(() => {
      const launcher = document.getElementById("aegis-launcher-orb");
      if (launcher) launcher.classList.remove("speaking");
      bindFallbackUnlock();
    });
  }

  function initAegisConciergeCard() {
    if (document.getElementById("aegis-concierge-card")) return;

    const isDashboard = window.location.pathname.includes("/dashboard");

    // 1. Create the WIT-h style White & Royal-Blue Assistant Card
    const card = document.createElement("div");
    card.id = "aegis-concierge-card";
    card.className = "aegis-concierge-card";

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
    launcher.title = "Open / Close ADX's BFF";
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
});

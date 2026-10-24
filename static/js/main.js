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
    if (!voices.length) return null;
    // Prefer local OS English voices first so Chrome/Edge plays immediately without cloud timeout
    const localEn = voices.find((v) => v.localService && v.lang && v.lang.toLowerCase().startsWith("en"));
    if (localEn) return localEn;
    return voices.find((v) => v.lang && v.lang.toLowerCase().startsWith("en")) || voices[0] || null;
  }

  window.speakAdxVoice = function (text, force = false) {
    if (!("speechSynthesis" in window)) return;
    if (voiceMuted && !force) return;

    // Force explicit letter-by-letter pronunciation ("A, D, X,") and strip "Group" so TTS never slurs "Adex Group"
    const spokenText = String(text || "")
      .replace(/\b(A\s*D\s*X|ADX|Adex)\s+Group\b/gi, "A, D, X,")
      .replace(/\b(A\s*D\s*X|ADX|Adex)\b/gi, "A, D, X,")
      .replace(/\bC\s*V\s*E\b/gi, "C, V, E,");

    try {
      if (window.speechSynthesis.speaking || window.speechSynthesis.pending) {
        window.speechSynthesis.cancel();
      }
      setTimeout(() => {
        try {
          window.speechSynthesis.resume();
          const utter = new SpeechSynthesisUtterance(spokenText);
          window._adxActiveUtterance = utter; // Prevent Chrome GC from dropping audio mid-speech
          const bestVoice = pickBestNeuralVoice();
          if (bestVoice) utter.voice = bestVoice;
          utter.lang = "en-US";
          utter.rate = 0.96;
          utter.pitch = 1.0;
          utter.volume = 1.0;

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
        } catch (innerErr) {}
      }, 65);
    } catch (e) {}
  };

  function getWelcomeGreeting() {
    if (voiceOrb && voiceOrb.dataset.greeting) {
      return voiceOrb.dataset.greeting;
    }
    return "Welcome to A, D, X. Silent Innovation. Absolute Defense. Enter your company domain to run a live 2026 C, V, E, security diagnostic.";
  }

  function triggerAutoWelcome() {
    if (hasWelcomed) return;
    hasWelcomed = true;
    window.speakAdxVoice(getWelcomeGreeting(), true);
  }

  if ("speechSynthesis" in window) {
    window.speechSynthesis.getVoices();
    window.speechSynthesis.onvoiceschanged = () => {
      pickBestNeuralVoice();
    };

    const onFirstInteract = (e) => {
      const closeBtn = document.getElementById("aegis-close-btn");
      if (closeBtn && closeBtn.contains(e.target)) return;
      if (voiceOrb && voiceOrb.contains(e.target)) return;
      if (!hasWelcomed) {
        triggerAutoWelcome();
      }
      document.removeEventListener("click", onFirstInteract);
    };
    document.addEventListener("click", onFirstInteract);
  }

  function initAegisConciergeCard() {
    if (!voiceOrb || document.getElementById("aegis-concierge-card")) return;

    const isDashboard = window.location.pathname.includes("/dashboard");
    const card = document.createElement("div");
    card.id = "aegis-concierge-card";
    card.className = "aegis-concierge-card";

    card.innerHTML = `
      <div class="aegis-card-header">
        <div class="aegis-header-left">
          <div class="aegis-avatar-wrap">
            <img src="/static/logo.svg?v=2026.14" alt="AEGIS" style="width: 24px; height: 24px;" />
            <span class="aegis-online-dot"></span>
          </div>
          <div>
            <div style="font-weight: 800; font-size: 0.92rem; line-height: 1.15;">AEGIS AI</div>
            <div style="font-size: 0.72rem; opacity: 0.9;">ADX Executive Security Concierge</div>
          </div>
        </div>
        <button type="button" class="aegis-close-btn" id="aegis-close-btn" title="Close Card">&times;</button>
      </div>
      <div class="aegis-card-body">
        <div style="color: #f8fafc; font-weight: 600; margin-bottom: 4px;">
          Hey, I'm AEGIS! 🛡️
        </div>
        <div style="line-height: 1.45;">
          I've got your back across ADX Cyber, Cloud &amp; AI Defense. What do you need help with today?
        </div>
        <div class="aegis-action-list">
          <div class="aegis-action-item" id="aegis-act-scan">
            <span>🛡️</span>
            <span>Run 6-Gate 2026 CVE Domain Audit</span>
          </div>
          <div class="aegis-action-item" id="aegis-act-ai">
            <span>🧠</span>
            <span>Ask AI Security Architect (GPT-4o)</span>
          </div>
          <div class="aegis-action-item" id="aegis-act-deploy">
            <span>⚡</span>
            <span>Deploy ADX Engineers ($350 Fixed Scope)</span>
          </div>
          <a href="mailto:contact@adxgroup.tech" class="aegis-action-item">
            <span>💬</span>
            <span>Reach Human Engineering Desk</span>
          </a>
        </div>
        <button type="button" class="aegis-cta-btn" id="aegis-cta-speak-chat">
          <span>🔊 Speak Welcome Brief Aloud</span>
        </button>
      </div>
    `;

    document.body.appendChild(card);

    const closeBtn = document.getElementById("aegis-close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        card.classList.add("closed");
        if ("speechSynthesis" in window && window.speechSynthesis.speaking) {
          window.speechSynthesis.cancel();
          if (voiceOrb) voiceOrb.classList.remove("speaking");
          if (voiceLabel) voiceLabel.textContent = "AEGIS Voice Brief";
        }
      });
    }

    document.getElementById("aegis-act-scan").addEventListener("click", () => {
      card.classList.add("closed");
      if (isDashboard && typeof switchConsoleTab === "function") {
        switchConsoleTab("scanner");
        const inp = document.getElementById("scan-domain-input");
        if (inp) inp.focus();
      } else {
        const inp = document.getElementById("landing-domain-input");
        if (inp) {
          inp.scrollIntoView({ behavior: "smooth", block: "center" });
          inp.focus();
        }
      }
    });

    document.getElementById("aegis-act-ai").addEventListener("click", () => {
      card.classList.add("closed");
      if (isDashboard && typeof switchConsoleTab === "function") {
        switchConsoleTab("ai");
        const inp = document.getElementById("ai-chat-input");
        if (inp) inp.focus();
      } else {
        window.location.href = "/login";
      }
    });

    document.getElementById("aegis-act-deploy").addEventListener("click", () => {
      card.classList.add("closed");
      if (isDashboard && typeof switchConsoleTab === "function") {
        switchConsoleTab("dispatch");
      } else {
        window.location.href = "/login";
      }
    });

    document.getElementById("aegis-cta-speak-chat").addEventListener("click", (e) => {
      e.stopPropagation();
      voiceMuted = false;
      hasWelcomed = true;
      window.speakAdxVoice(getWelcomeGreeting(), true);
    });
  }

  initAegisConciergeCard();

  if (voiceOrb) {
    voiceOrb.addEventListener("click", (e) => {
      e.stopPropagation();
      const card = document.getElementById("aegis-concierge-card");
      if (card) {
        card.classList.toggle("closed");
      }
      voiceMuted = false;
      hasWelcomed = true;
      window.speakAdxVoice(getWelcomeGreeting(), true);
    });
  }

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

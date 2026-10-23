document.addEventListener("DOMContentLoaded", () => {
  // 1. Live 5-Vector Domain Security Diagnostic Scanner
  const scanForm = document.getElementById("scan-form");
  const domainInput = document.getElementById("scan-domain-input");
  const scanBtn = document.getElementById("scan-submit-btn");
  const resultsBox = document.getElementById("scan-results");
  const scoreValue = document.getElementById("scan-score-val");
  const gradeBadge = document.getElementById("scan-grade-badge");
  const domainTitle = document.getElementById("scan-domain-title");
  const aiSummaryText = document.getElementById("scan-ai-summary");
  const gatesTableBody = document.getElementById("gates-table-body");
  const outreachTextarea = document.getElementById("outreach-email-text");
  const copyOutreachBtn = document.getElementById("copy-outreach-btn");

  if (scanForm) {
    scanForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = domainInput.value.trim();
      if (!domain) return;

      scanBtn.disabled = true;
      scanBtn.textContent = "Running 5-Vector Diagnostics...";

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        });
        const payload = await res.json();
        if (!res.ok || !payload.ok) {
          alert(payload.detail || "Could not complete scan. Verify the domain name.");
          return;
        }

        const data = payload.data;
        const isAuth = Boolean(data.is_authenticated);

        resultsBox.classList.remove("hidden");
        domainTitle.textContent = `${data.domain} | Diagnostic Report (${data.timestamp})`;
        scoreValue.textContent = `${data.score}/100`;
        gradeBadge.textContent = `GRADE ${data.grade} | ${data.risk_level}`;
        aiSummaryText.textContent = data.ai_executive_summary;

        if (outreachTextarea) {
          if (isAuth) {
            outreachTextarea.value = data.outreach_email;
          } else {
            outreachTextarea.value =
              "🔒 Sign in to your free ADX Group Console (via Google, GitHub, or Work Email) at /login to unlock the full copy-paste remediation configurations, export executive reports, and add this domain to your 24/7 monitoring watchlist.";
          }
        }

        gatesTableBody.innerHTML = "";
        data.gates.forEach((g) => {
          const tr = document.createElement("tr");
          const badgeClass = g.state ? "badge-true" : "badge-false";
          let remediationHtml = "";

          if (g.remediation) {
            if (isAuth) {
              remediationHtml = `<div class="remediation-code"><strong>Fix:</strong> ${escapeHtml(g.remediation)}</div>`;
            } else {
              remediationHtml = `
                <div class="remediation-code" style="display: flex; justify-content: space-between; align-items: center; gap: 10px;">
                  <span>🔒 Exact server/DNS fix available in Client Console</span>
                  <a href="/login" style="color: var(--accent-cyan); font-weight: 700; text-decoration: none;">Sign In to Unlock →</a>
                </div>
              `;
            }
          }

          tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-weight: 700;">${escapeHtml(g.gate_id)}</td>
            <td>
              <strong>${escapeHtml(g.vector)}</strong>
              <div style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(g.condition)}</div>
            </td>
            <td><span class="${badgeClass}">${escapeHtml(g.status_label)}</span></td>
            <td>
              <div>${escapeHtml(g.finding)}</div>
              ${remediationHtml}
            </td>
          `;
          gatesTableBody.appendChild(tr);
        });
      } catch (err) {
        alert("Network error while running diagnostic scan.");
      } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Run Deep Diagnostic";
      }
    });
  }

  if (copyOutreachBtn) {
    copyOutreachBtn.addEventListener("click", () => {
      outreachTextarea.select();
      navigator.clipboard.writeText(outreachTextarea.value);
      const original = copyOutreachBtn.textContent;
      copyOutreachBtn.textContent = "Copied to Clipboard ✓";
      setTimeout(() => {
        copyOutreachBtn.textContent = original;
      }, 2200);
    });
  }

  // 2. 24/7 ADX AI Systems Consultant
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

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message }),
        });
        const payload = await res.json();
        if (payload.ok && payload.data) {
          appendChatMessage(payload.data.reply, "chat-bot");
        } else {
          appendChatMessage("Please reach us directly at contact@adxgroup.tech.", "chat-bot");
        }
      } catch (err) {
        appendChatMessage("Connection interrupted. Email contact@adxgroup.tech for immediate support.", "chat-bot");
      }
    });
  }

  function appendChatMessage(text, className) {
    const div = document.createElement("div");
    div.className = `chat-msg ${className}`;
    div.textContent = text;
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  // 3. Client Project & Audit Inquiry Form (Gate 4)
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

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
});

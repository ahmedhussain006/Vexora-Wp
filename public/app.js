/**
 * VEXORAWP WEB APPLICATION CONTROLLER
 * Full client-side dashboard, progress HUD, and report generation
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const scanForm = document.getElementById('scan-form');
  const targetUrlInput = document.getElementById('target-url-input');
  const btnStartScan = document.getElementById('btn-start-scan');
  const progressHud = document.getElementById('scan-progress-hud');
  const hudProgressBar = document.getElementById('hud-progress-bar');
  const hudStatusTitle = document.getElementById('hud-status-title');
  const hudStatusSubtitle = document.getElementById('hud-status-subtitle');
  const errorAlert = document.getElementById('error-alert');
  const errorTitle = document.getElementById('error-title');
  const errorMessage = document.getElementById('error-message');
  const btnCloseError = document.getElementById('btn-close-error');
  const resultsDashboard = document.getElementById('results-dashboard');

  // History Drawer Elements
  const btnToggleHistory = document.getElementById('btn-toggle-history');
  const historyDrawer = document.getElementById('history-drawer');
  const btnCloseDrawer = document.getElementById('btn-close-drawer');
  const historyItemsContainer = document.getElementById('history-items');
  const historyCounter = document.getElementById('history-counter');
  const btnClearHistory = document.getElementById('btn-clear-history');

  // Export Buttons
  const btnExportHtml = document.getElementById('btn-export-html');
  const btnExportJson = document.getElementById('btn-export-json');
  const btnNewScan = document.getElementById('btn-new-scan');
  const btnCopyJson = document.getElementById('btn-copy-json');

  let currentReport = null;
  let progressInterval = null;

  // Initialize History
  updateHistoryUI();

  // Preset Sample Targets
  document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      targetUrlInput.value = btn.dataset.url;
      targetUrlInput.focus();
    });
  });

  // Tab Navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanel = document.getElementById(btn.dataset.tab);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  // Vuln Filter Buttons
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      filterVulns(pill.dataset.vulnFilter);
    });
  });

  // Form Submission
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    let url = targetUrlInput.value.trim();
    if (!url) return;

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
      targetUrlInput.value = url;
    }

    const mode = document.querySelector('input[name="scan-mode"]:checked')?.value || 'quick';
    startAudit(url, mode);
  });

  // Start Audit Process
  async function startAudit(url, mode) {
    hideError();
    resultsDashboard.classList.add('hidden');
    progressHud.classList.remove('hidden');
    btnStartScan.disabled = true;

    startProgressSimulation(mode);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, mode })
      });

      const data = await response.json();
      stopProgressSimulation();

      if (!response.ok || data.error) {
        showError('Audit Unsuccessful', data.error || 'Failed to analyze target. Verify site is reachable and WordPress is installed.');
        progressHud.classList.add('hidden');
        btnStartScan.disabled = false;
        return;
      }

      currentReport = data;
      saveScanToHistory(data);
      renderDashboard(data);

      progressHud.classList.add('hidden');
      resultsDashboard.classList.remove('hidden');
      btnStartScan.disabled = false;

      resultsDashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      stopProgressSimulation();
      progressHud.classList.add('hidden');
      btnStartScan.disabled = false;
      showError('Connection Error', `Could not connect to scan service: ${err.message}`);
    }
  }

  // Progress HUD Simulation
  function startProgressSimulation(mode) {
    const steps = [
      { pct: 15, title: 'Resolving Target & Testing WordPress...', sub: 'Checking wp-login, REST API & Core Headers', stepId: 'step-1' },
      { pct: 35, title: 'Fingerprinting Server & WAF...', sub: 'Identifying PHP, LiteSpeed/Nginx & CDN Signatures', stepId: 'step-2' },
      { pct: 55, title: 'Enumerating Users & Authors...', sub: 'Probing /wp/v2/users and author redirect IDORs', stepId: 'step-3' },
      { pct: 75, title: 'Probing Common WordPress Plugins...', sub: 'Concurrent inspection of plugin readme.txt headers', stepId: 'step-4' },
      { pct: 88, title: 'Checking Sensitive File Exposures...', sub: 'Auditing .env, db.sql, backup.zip & debug logs', stepId: 'step-5' },
      { pct: 95, title: 'Correlating CVE Intelligence...', sub: 'Evaluating version-based security posture score', stepId: 'step-6' }
    ];

    let currentStep = 0;
    hudProgressBar.style.width = '10%';
    document.querySelectorAll('.hud-step').forEach(s => s.className = 'hud-step');

    const duration = mode === 'quick' ? 600 : 1200;

    progressInterval = setInterval(() => {
      if (currentStep < steps.length) {
        const s = steps[currentStep];
        hudProgressBar.style.width = `${s.pct}%`;
        hudStatusTitle.textContent = s.title;
        hudStatusSubtitle.textContent = s.sub;

        document.querySelectorAll('.hud-step').forEach((el, idx) => {
          if (idx < currentStep) el.className = 'hud-step done';
          else if (idx === currentStep) el.className = 'hud-step active';
          else el.className = 'hud-step';
        });

        currentStep++;
      }
    }, duration);
  }

  function stopProgressSimulation() {
    if (progressInterval) {
      clearInterval(progressInterval);
      progressInterval = null;
    }
    hudProgressBar.style.width = '100%';
    document.querySelectorAll('.hud-step').forEach(el => el.className = 'hud-step done');
  }

  // Error Handling
  function showError(title, msg) {
    errorTitle.textContent = title;
    errorMessage.textContent = msg;
    errorAlert.classList.remove('hidden');
    errorAlert.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function hideError() {
    errorAlert.classList.add('hidden');
  }

  btnCloseError.addEventListener('click', hideError);

  // Render Dashboard
  function renderDashboard(report) {
    const r = report.results || {};
    const scoreInfo = report.security_score || { score: 100, grade: 'A', rating: 'Excellent', deductions: [] };

    // Topbar info
    document.getElementById('res-target-url').textContent = report.target || 'Target';
    document.getElementById('res-scan-time').textContent = `Audited: ${new Date(report.scanned_at).toLocaleTimeString()}`;
    document.getElementById('res-scan-mode').textContent = `Mode: ${report.mode === 'full' ? 'Deep Audit' : 'Fast Recon'}`;

    // Score & Gauge
    const score = scoreInfo.score;
    const grade = scoreInfo.grade || 'A';
    document.getElementById('score-number').textContent = score;

    const gradeBadge = document.getElementById('grade-badge');
    gradeBadge.textContent = `GRADE ${grade}`;
    gradeBadge.className = `grade-badge grade-${grade.toLowerCase()}`;

    document.getElementById('rating-title').textContent = scoreInfo.rating || 'Security Posture';
    document.getElementById('rating-description').textContent =
      score >= 80 ? 'Site shows strong defensive posture with limited surface disclosure.' :
      score >= 65 ? 'Moderate exposure detected. Review recommendations below.' :
      'Critical risk identified. Immediate vulnerability patching needed.';

    // Animate SVG Gauge
    const gaugeFill = document.getElementById('gauge-fill');
    const circumference = 364.4;
    const offset = circumference - (circumference * score / 100);
    gaugeFill.style.strokeDashoffset = offset;

    const colorMap = {
      'A': '#10b981',
      'B': '#3b82f6',
      'C': '#f59e0b',
      'D': '#8b5cf6',
      'F': '#ef4444'
    };
    gaugeFill.style.stroke = colorMap[grade] || '#10b981';

    // Deductions Box
    const deductionsBox = document.getElementById('deductions-box');
    const deductionsList = document.getElementById('deductions-list');
    deductionsList.innerHTML = '';
    if (scoreInfo.deductions && scoreInfo.deductions.length > 0) {
      scoreInfo.deductions.forEach(d => {
        const li = document.createElement('li');
        li.textContent = d;
        deductionsList.appendChild(li);
      });
      deductionsBox.classList.remove('hidden');
    } else {
      deductionsBox.classList.add('hidden');
    }

    // KPI Quad
    const vulns = r.vulnerabilities || [];
    const activeVulns = vulns.filter(v => v.status === 'VULNERABLE');
    document.getElementById('kpi-vulns').textContent = activeVulns.length;
    document.getElementById('tab-count-vulns').textContent = vulns.length;

    const exposures = (r.security && r.security.exposures) || [];
    const openExposures = exposures.filter(e => e.status === 200);
    document.getElementById('kpi-exposures').textContent = openExposures.length;
    document.getElementById('tab-count-exposures').textContent = exposures.length;

    const users = r.users || [];
    document.getElementById('kpi-users').textContent = users.length;
    document.getElementById('tab-count-users').textContent = users.length;

    const headers = (r.security && r.security.headers) || {};
    const missingHeaders = Object.keys(headers).filter(k => headers[k] === 'MISSING');
    document.getElementById('kpi-headers').textContent = missingHeaders.length;

    const plugins = r.plugins || [];
    document.getElementById('tab-count-plugins').textContent = plugins.length;

    // Render Tab 1: Vulns
    renderVulnsTable(vulns);

    // Render Tab 2: Exposures
    renderExposuresTable(exposures);

    // Render Tab 3: Security Headers
    renderHeadersGrid(headers);

    // Render Tab 4: Users & OSINT
    renderUsersTable(users);
    renderOsint(r.emails || [], (r.social_contact && r.social_contact.social_media) || {});

    // Render Tab 5: Plugins & Themes
    renderPluginsAndThemes(plugins, r.themes || []);

    // Render Tab 6: Server & Tech
    renderServerAndTech(r.server_info || {});

    // Render Tab 7: Raw JSON
    document.getElementById('raw-json-output').textContent = JSON.stringify(report, null, 2);
  }

  // Sub-renderers
  function renderVulnsTable(vulns) {
    const tbody = document.getElementById('vulns-tbody');
    tbody.innerHTML = '';

    if (!vulns || vulns.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--green-500); padding: 24px;">No known CVE matches detected for installed plugins.</td></tr>';
      return;
    }

    vulns.forEach(v => {
      const st = v.status || 'UNVERIFIED';
      const sev = (v.severity || 'HIGH').toUpperCase();
      const stClass = st === 'VULNERABLE' ? 'badge-danger' : st === 'PATCHED' ? 'badge-success' : 'badge-warning';
      const sevClass = (sev === 'CRITICAL' || sev === 'HIGH') ? 'badge-danger' : 'badge-warning';

      const tr = document.createElement('tr');
      tr.dataset.status = st;
      tr.innerHTML = `
        <td><strong>${escapeHtml(v.plugin)}</strong></td>
        <td><span class="badge badge-cve">${escapeHtml(v.cve)}</span></td>
        <td><span class="badge ${sevClass}">${escapeHtml(sev)}</span></td>
        <td><span class="badge ${stClass}">${escapeHtml(st)}</span></td>
        <td>${escapeHtml(v.desc || '')}</td>
        <td><code>Fixed: ${escapeHtml(v.fixed_in || 'N/A')}</code><br><small class="text-dim">Installed: ${escapeHtml(v.version || '?')}</small></td>
      `;
      tbody.appendChild(tr);
    });
  }

  function filterVulns(status) {
    const rows = document.querySelectorAll('#vulns-tbody tr');
    rows.forEach(tr => {
      if (status === 'all' || tr.dataset.status === status) {
        tr.style.display = '';
      } else {
        tr.style.display = 'none';
      }
    });
  }

  function renderExposuresTable(exposures) {
    const tbody = document.getElementById('exposures-tbody');
    tbody.innerHTML = '';

    if (!exposures || exposures.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--green-500); padding: 24px;">No sensitive files or backups exposed.</td></tr>';
      return;
    }

    exposures.forEach(e => {
      const stClass = e.status === 200 ? 'badge-danger' : 'badge-warning';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(e.label)}</strong></td>
        <td><code>${escapeHtml(e.path)}</code></td>
        <td><span class="badge ${stClass}">HTTP ${e.status}</span></td>
        <td>${(e.size || 0).toLocaleString()} bytes</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function renderHeadersGrid(headers) {
    const grid = document.getElementById('headers-grid');
    grid.innerHTML = '';

    Object.keys(headers).forEach(h => {
      const isMissing = headers[h] === 'MISSING';
      const card = document.createElement('div');
      card.className = `header-card ${isMissing ? 'missing' : 'present'}`;
      card.innerHTML = `
        <div class="h-top">
          <span class="h-name">${escapeHtml(h)}</span>
          <span class="badge ${isMissing ? 'badge-danger' : 'badge-success'}">${isMissing ? 'MISSING' : 'PRESENT'}</span>
        </div>
        <div class="h-val" title="${escapeHtml(headers[h])}">${escapeHtml(headers[h])}</div>
      `;
      grid.appendChild(card);
    });
  }

  function renderUsersTable(users) {
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '';

    if (!users || users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--green-500); padding: 24px;">No users publicly enumerated.</td></tr>';
      return;
    }

    users.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(String(u.id))}</td>
        <td><strong>${escapeHtml(u.login)}</strong></td>
        <td>${escapeHtml(u.name || '—')}</td>
        <td><span class="badge badge-info">${escapeHtml(u.source || 'REST API')}</span></td>
        <td>${u.url ? `<a href="${escapeHtml(u.url)}" target="_blank" rel="noopener" style="color: var(--cyan-400);">Profile</a>` : '—'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function renderOsint(emails, social) {
    const emailsList = document.getElementById('emails-list');
    emailsList.innerHTML = '';
    if (emails.length === 0) {
      emailsList.innerHTML = '<li style="color: var(--text-dim);">No emails scraped.</li>';
    } else {
      emails.forEach(e => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>${escapeHtml(e.email)}</strong> <small class="text-dim">(${escapeHtml(e.context || '')})</small>`;
        emailsList.appendChild(li);
      });
    }

    const socialList = document.getElementById('social-list');
    socialList.innerHTML = '';
    const platforms = Object.keys(social);
    if (platforms.length === 0) {
      socialList.innerHTML = '<li style="color: var(--text-dim);">No social handles found.</li>';
    } else {
      platforms.forEach(p => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>${escapeHtml(p)}:</strong> ${escapeHtml(social[p].join(', '))}`;
        socialList.appendChild(li);
      });
    }
  }

  function renderPluginsAndThemes(plugins, themes) {
    const pBody = document.getElementById('plugins-tbody');
    pBody.innerHTML = '';
    if (plugins.length === 0) {
      pBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-dim); padding:16px;">No plugins detected.</td></tr>';
    } else {
      plugins.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(p.name || p.slug)}</strong></td>
          <td><span class="badge badge-info">v${escapeHtml(p.version || 'unknown')}</span></td>
          <td><small class="text-dim">${escapeHtml(p.source || '')}</small></td>
        `;
        pBody.appendChild(tr);
      });
    }

    const tBody = document.getElementById('themes-tbody');
    tBody.innerHTML = '';
    if (themes.length === 0) {
      tBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-dim); padding:16px;">No themes detected.</td></tr>';
    } else {
      themes.forEach(t => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(t.name || t.slug)}</strong></td>
          <td>v${escapeHtml(t.version || '?')}</td>
          <td>${escapeHtml(t.author || '—')}</td>
        `;
        tBody.appendChild(tr);
      });
    }
  }

  function renderServerAndTech(server) {
    document.getElementById('server-val').textContent = server.server || 'Unknown';
    document.getElementById('php-val').textContent = server.php_version || server.x_powered_by || 'Not Disclosed';
    document.getElementById('ssl-issuer-val').textContent = (server.ssl_issuer && server.ssl_issuer.O) || '—';
    document.getElementById('ssl-expiry-val').textContent = server.ssl_expires || '—';

    const wafRow = document.getElementById('waf-badges');
    wafRow.innerHTML = '';
    const wafs = server.waf_cdn || [];
    if (wafs.length === 0) {
      wafRow.textContent = 'None detected';
    } else {
      wafs.forEach(w => {
        const b = document.createElement('span');
        b.className = 'badge badge-info';
        b.textContent = w;
        wafRow.appendChild(b);
      });
    }

    const techRow = document.getElementById('tech-badges');
    techRow.innerHTML = '';
    const techs = server.technologies || [];
    if (techs.length === 0) {
      techRow.textContent = 'None detected';
    } else {
      techs.forEach(t => {
        const b = document.createElement('span');
        b.className = 'badge badge-tech';
        b.textContent = t;
        techRow.appendChild(b);
      });
    }
  }

  // Export JSON
  btnExportJson.addEventListener('click', () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `vexorawp_${cleanDomain(currentReport.target)}_report.json`);
  });

  // Export Standalone HTML Report
  btnExportHtml.addEventListener('click', () => {
    if (!currentReport) return;
    const htmlString = generateClientHtmlReport(currentReport);
    const blob = new Blob([htmlString], { type: 'text/html;charset=utf-8' });
    downloadBlob(blob, `vexorawp_${cleanDomain(currentReport.target)}_report.html`);
  });

  // Copy JSON
  btnCopyJson.addEventListener('click', () => {
    if (!currentReport) return;
    navigator.clipboard.writeText(JSON.stringify(currentReport, null, 2));
    btnCopyJson.querySelector('span').textContent = 'Copied!';
    setTimeout(() => {
      btnCopyJson.querySelector('span').textContent = 'Copy JSON';
    }, 1500);
  });

  // New Scan Button
  btnNewScan.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    targetUrlInput.select();
  });

  // History Management
  function saveScanToHistory(report) {
    let history = getHistory();
    history = history.filter(h => h.target !== report.target);
    history.unshift({
      target: report.target,
      score: report.security_score?.score ?? 100,
      grade: report.security_score?.grade ?? 'A',
      scanned_at: report.scanned_at,
      report: report
    });
    if (history.length > 10) history.pop();
    localStorage.setItem('vexora_history', JSON.stringify(history));
    updateHistoryUI();
  }

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem('vexora_history')) || [];
    } catch {
      return [];
    }
  }

  function updateHistoryUI() {
    const history = getHistory();
    historyCounter.textContent = history.length;
    historyItemsContainer.innerHTML = '';

    if (history.length === 0) {
      historyItemsContainer.innerHTML = '<p class="empty-history">No past audits recorded.</p>';
      return;
    }

    history.forEach(item => {
      const div = document.createElement('div');
      div.className = 'history-item';
      div.innerHTML = `
        <span class="h-item-url">${escapeHtml(item.target)}</span>
        <div class="h-item-meta">
          <span class="badge grade-${item.grade.toLowerCase()}">Grade ${item.grade} (${item.score}/100)</span>
          <span>${new Date(item.scanned_at).toLocaleDateString()}</span>
        </div>
      `;
      div.addEventListener('click', () => {
        currentReport = item.report;
        renderDashboard(item.report);
        resultsDashboard.classList.remove('hidden');
        historyDrawer.classList.add('hidden');
        resultsDashboard.scrollIntoView({ behavior: 'smooth' });
      });
      historyItemsContainer.appendChild(div);
    });
  }

  btnToggleHistory.addEventListener('click', () => {
    historyDrawer.classList.toggle('hidden');
  });

  btnCloseDrawer.addEventListener('click', () => {
    historyDrawer.classList.add('hidden');
  });

  btnClearHistory.addEventListener('click', () => {
    localStorage.removeItem('vexora_history');
    updateHistoryUI();
  });

  // Helper Utilities
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function cleanDomain(url) {
    try {
      return new URL(url).hostname.replace(/[^a-zA-Z0-9]/g, '_');
    } catch {
      return 'target';
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Client-Side Standalone HTML Report Builder
  function generateClientHtmlReport(data) {
    const target = escapeHtml(data.target);
    const date = escapeHtml(data.scanned_at);
    const s = data.security_score || { score: 100, grade: 'A', rating: 'Good' };
    const r = data.results || {};

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VexoraWP Report — ${target}</title>
<style>
body { background: #0b0f19; color: #f1f5f9; font-family: sans-serif; padding: 30px; }
.card { background: #131b2e; border: 1px solid #1f2d47; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
h1, h2, h3 { color: #06b6d4; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
th, td { padding: 10px; border-bottom: 1px solid #1f2d47; text-align: left; }
th { background: #0f172a; color: #94a3b8; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-weight: 700; font-size: 11px; }
.grade { font-size: 24px; font-weight: 800; color: #10b981; }
</style>
</head>
<body>
  <h1>VexoraWP Security Audit Report</h1>
  <p><strong>Target:</strong> ${target} | <strong>Date:</strong> ${date}</p>
  <div class="card">
    <h2>Overall Posture: <span class="grade">Grade ${s.grade} (${s.score}/100)</span></h2>
    <p>${escapeHtml(s.rating)}</p>
  </div>
  <div class="card">
    <h3>Detected Plugins & Known CVEs</h3>
    <table>
      <thead><tr><th>Plugin</th><th>CVE</th><th>Severity</th><th>Status</th></tr></thead>
      <tbody>
        ${(r.vulnerabilities || []).map(v => `<tr><td>${escapeHtml(v.plugin)}</td><td>${escapeHtml(v.cve)}</td><td>${escapeHtml(v.severity)}</td><td>${escapeHtml(v.status)}</td></tr>`).join('') || '<tr><td colspan="4">No known CVEs.</td></tr>'}
      </tbody>
    </table>
  </div>
  <div class="card">
    <h3>Exposed Sensitive Paths</h3>
    <table>
      <thead><tr><th>Label</th><th>Path</th><th>Status</th></tr></thead>
      <tbody>
        ${(r.security?.exposures || []).map(e => `<tr><td>${escapeHtml(e.label)}</td><td><code>${escapeHtml(e.path)}</code></td><td>HTTP ${e.status}</td></tr>`).join('') || '<tr><td colspan="3">None exposed.</td></tr>'}
      </tbody>
    </table>
  </div>
</body>
</html>`;
  }
});

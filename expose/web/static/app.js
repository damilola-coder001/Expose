// Expose Web Client - Security Intelligence Platform Interface Overhaul
// Evidence First. Intelligence Second.

let currentScanResult = null;
let currentSeverityFilter = 'ALL';
let currentCategoryFilter = 'ALL';
let searchQuery = '';
let isPassedChecksExpanded = true;
let activeAttackSurfaceTab = 'pages';
let isServerlessRuntime = false;

document.addEventListener('DOMContentLoaded', () => {
  // Theme Toggle Management
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeToggleText = document.getElementById('themeToggleText');

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (themeToggleText) {
      themeToggleText.textContent = theme === 'dark' ? 'Dark' : 'Light';
    }
    if (themeToggleBtn) {
      themeToggleBtn.setAttribute('title', `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`);
      themeToggleBtn.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`);
    }
  }

  const initialTheme = document.documentElement.getAttribute('data-theme') || (function() {
    try {
      return localStorage.getItem('expose_theme') || 'dark';
    } catch (e) {
      return 'dark';
    }
  })();
  applyTheme(initialTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const targetTheme = current === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem('expose_theme', targetTheme);
      } catch (e) {}
      applyTheme(targetTheme);
    });
  }

  // Main form elements
  const scanForm = document.getElementById('scanForm');
  const targetInput = document.getElementById('targetInput');
  const allowPrivateToggle = document.getElementById('allowPrivateToggle');
  const analyzeBtn = document.getElementById('analyzeBtn');

  // State sections
  const scanningState = document.getElementById('scanningState');
  const resultsSection = document.getElementById('resultsSection');
  const errorBanner = document.getElementById('errorBanner');

  // Quick Action Buttons
  const rescanBtn = document.getElementById('rescanBtn');
  const shareReportBtn = document.getElementById('shareReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const downloadSarifBtn = document.getElementById('downloadSarifBtn');
  const startFixingBtn = document.getElementById('startFixingBtn');

  // Modal elements
  const openScoreModalBtn = document.getElementById('openScoreModalBtn');
  const closeScoreModalBtn = document.getElementById('closeScoreModalBtn');
  const closeScoreModalFooterBtn = document.getElementById('closeScoreModalFooterBtn');
  const scoreModalBackdrop = document.getElementById('scoreModalBackdrop');

  // Search & Filtering
  const findingSearchInput = document.getElementById('findingSearchInput');
  const clearSearchBtn = document.getElementById('clearSearchBtn');

  // Serverless providers do not preserve process memory between requests.
  // Detect that mode once so scans return their result in the initiating call.
  fetch('/api/v1/config/telemetry', { cache: 'no-store' })
    .then(response => response.ok ? response.json() : {})
    .then(data => { isServerlessRuntime = data.serverless_runtime === true; })
    .catch(() => { isServerlessRuntime = false; });

  // Rescan Action
  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => {
      if (!currentScanResult) return;
      targetInput.value = currentScanResult.target.normalized_url || currentScanResult.target.host;
      window.scrollTo({ top: 0, behavior: 'smooth' });
      scanForm.dispatchEvent(new Event('submit', { cancelable: true }));
    });
  }

  // Share Action
  if (shareReportBtn) {
    shareReportBtn.addEventListener('click', () => {
      if (!currentScanResult) return;
      const shareUrl = `${window.location.origin}/?scan=${encodeURIComponent(currentScanResult.scan_id)}`;
      navigator.clipboard.writeText(shareUrl).then(() => {
        showToast('Report permalink copied to clipboard!');
      }).catch(() => {
        showToast(`Scan ID: ${currentScanResult.scan_id}`);
      });
    });
  }

  // Export JSON Report (Phase 25)
  if (downloadJsonBtn) {
    downloadJsonBtn.addEventListener('click', () => {
      if (!currentScanResult) return;
      if (isServerlessRuntime) {
        const report = JSON.stringify(currentScanResult, null, 2);
        const blob = new Blob([report], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `expose-${currentScanResult.scan_id}.json`;
        link.click();
        URL.revokeObjectURL(url);
        return;
      }
      window.location.href = `/api/v1/scans/${currentScanResult.scan_id}/export/json`;
    });
  }

  // Export OASIS SARIF v2.1.0 Report (Phase 26)
  if (downloadSarifBtn) {
    downloadSarifBtn.addEventListener('click', () => {
      if (!currentScanResult) return;
      if (isServerlessRuntime) {
        showToast('SARIF export requires persistent report storage and is unavailable in this serverless deployment.');
        return;
      }
      window.location.href = `/api/v1/scans/${currentScanResult.scan_id}/export/sarif`;
    });
  }

  // "Start Fixing" CTA - jumps to first priority issue
  if (startFixingBtn) {
    startFixingBtn.addEventListener('click', () => {
      const fixFirstSec = document.getElementById('sec-fix-first');
      if (fixFirstSec) {
        fixFirstSec.scrollIntoView({ behavior: 'smooth' });
        const firstCard = fixFirstSec.querySelector('.finding-card');
        if (firstCard) {
          firstCard.classList.add('highlight-glow');
          setTimeout(() => firstCard.classList.remove('highlight-glow'), 1800);
        }
      }
    });
  }

  // Score Methodology Modal Handlers
  if (openScoreModalBtn) {
    openScoreModalBtn.addEventListener('click', () => {
      renderScoreMethodology();
      scoreModalBackdrop.classList.remove('hidden');
    });
  }

  const closeModal = () => scoreModalBackdrop.classList.add('hidden');
  if (closeScoreModalBtn) closeScoreModalBtn.addEventListener('click', closeModal);
  if (closeScoreModalFooterBtn) closeScoreModalFooterBtn.addEventListener('click', closeModal);
  if (scoreModalBackdrop) {
    scoreModalBackdrop.addEventListener('click', (e) => {
      if (e.target === scoreModalBackdrop) closeModal();
    });
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !scoreModalBackdrop.classList.contains('hidden')) {
      closeModal();
    }
  });

  // Search Input Handler
  if (findingSearchInput) {
    findingSearchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.trim().toLowerCase();
      if (clearSearchBtn) {
        if (searchQuery) clearSearchBtn.classList.remove('hidden');
        else clearSearchBtn.classList.add('hidden');
      }
      renderDiagnostics();
    });
  }

  if (clearSearchBtn) {
    clearSearchBtn.addEventListener('click', () => {
      findingSearchInput.value = '';
      searchQuery = '';
      clearSearchBtn.classList.add('hidden');
      renderDiagnostics();
    });
  }

  // Severity Counts Filter Clicks
  document.querySelectorAll('.sev-count-item').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const item = e.currentTarget;
      const filter = item.dataset.filter;

      if (filter === 'PASSED') {
        const passedSection = document.getElementById('sec-passed');
        const passedContainer = document.getElementById('passedContainer');
        isPassedChecksExpanded = true;
        passedContainer.classList.remove('hidden');
        document.getElementById('passedToggleHint').textContent = 'Click to collapse';
        passedSection.scrollIntoView({ behavior: 'smooth' });
        return;
      }

      document.querySelectorAll('.sev-count-item').forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      item.classList.add('active');
      item.setAttribute('aria-selected', 'true');
      currentSeverityFilter = filter;
      renderDiagnostics();

      const diagSection = document.getElementById('sec-diagnostics');
      diagSection.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Passed Checks Section Toggle
  const passedToggle = document.getElementById('passedToggle');
  if (passedToggle) {
    const handleToggle = () => {
      const container = document.getElementById('passedContainer');
      const hint = document.getElementById('passedToggleHint');
      isPassedChecksExpanded = !isPassedChecksExpanded;
      if (isPassedChecksExpanded) {
        container.classList.remove('hidden');
        hint.textContent = 'Click to collapse';
        passedToggle.setAttribute('aria-expanded', 'true');
      } else {
        container.classList.add('hidden');
        hint.textContent = 'Click to expand';
        passedToggle.setAttribute('aria-expanded', 'false');
      }
    };
    passedToggle.addEventListener('click', handleToggle);
    passedToggle.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleToggle();
      }
    });
  }

  // Attack Surface Tabs Switching
  document.querySelectorAll('.as-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      document.querySelectorAll('.as-tab').forEach(t => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
      });
      const t = e.currentTarget;
      t.classList.add('active');
      t.setAttribute('aria-selected', 'true');
      activeAttackSurfaceTab = t.dataset.tab;
      renderAttackSurfaceContent();
    });
  });

  // Sticky Navigation Spy
  setupStickyNavSpy();

  // Scan Form Submission
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const rawTarget = targetInput.value.trim();
    if (!rawTarget) return;

    // Reset UI state
    errorBanner.classList.add('hidden');
    resultsSection.classList.add('hidden');
    scanningState.classList.remove('hidden');
    analyzeBtn.disabled = true;

    resetProbeMilestones();

    try {
      const scanRequest = {
        target: rawTarget,
        allow_private: allowPrivateToggle.checked,
        enable_ai: false // On-demand AI only
      };

      if (isServerlessRuntime) {
        document.getElementById('scanProgressSubtitle').textContent = 'Running serverless assessment. This may take up to one minute.';
        const syncResponse = await fetch('/api/v1/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(scanRequest)
        });
        const data = await syncResponse.json();
        if (!syncResponse.ok || !data.target) {
          throw new Error(data.detail || 'Assessment failed to complete.');
        }

        currentScanResult = data;
        renderScanResult(data);
        return;
      }

      // 1. Initiate asynchronous scan (Phase 24)
      const initResponse = await fetch('/api/v1/scans/async', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanRequest)
      });

      const initData = await initResponse.json();
      if (!initResponse.ok) {
        throw new Error(initData.detail || 'Assessment failed to initialize.');
      }

      const scanId = initData.scan_id;

      // 2. Stream real-time probe milestone events via SSE (Phase 24)
      await new Promise((resolve) => {
        const evtSource = new EventSource(`/api/v1/scans/${scanId}/events`);

        evtSource.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.stage) {
              updateScanProgressMilestone(payload.stage, payload.detail);
            }
          } catch (err) {}
        };

        evtSource.addEventListener('done', () => {
          evtSource.close();
          resolve();
        });

        evtSource.addEventListener('error', () => {
          evtSource.close();
          resolve();
        });

        // 45s safety timeout
        setTimeout(() => {
          evtSource.close();
          resolve();
        }, 45000);
      });

      // 3. Fetch completed scan result with polling resilience
      let data = null;
      for (let attempt = 0; attempt < 50; attempt++) {
        const finalResponse = await fetch(`/api/v1/scans/${scanId}`);
        const resJson = await finalResponse.json();

        if (finalResponse.status === 200 && resJson.target) {
          data = resJson;
          break;
        } else if (finalResponse.status === 202) {
          await new Promise(r => setTimeout(r, 1200));
        } else {
          throw new Error(resJson.detail || 'Assessment failed to complete.');
        }
      }

      if (!data || !data.target) {
        throw new Error('Assessment timed out while processing results.');
      }

      currentScanResult = data;
      renderScanResult(data);
      if (!isServerlessRuntime) fetchTargetHistoryAndDiff(data.target.host, data.scan_id);
    } catch (err) {
      showError('Assessment Blocked / Error', err.message);
    } finally {
      scanningState.classList.add('hidden');
      analyzeBtn.disabled = false;
    }
  });
});

// Milestone progress tracking
const MILESTONE_ELEMENTS = {
  'Connecting': 'stage-connecting',
  'Fetching website': 'stage-fetching',
  'Analyzing TLS': 'stage-tls',
  'Inspecting headers': 'stage-headers',
  'Discovering assets': 'stage-assets',
  'Running security rules': 'stage-rules',
  'Validating findings': 'stage-validating',
  'Calculating risk': 'stage-risk',
};

function resetProbeMilestones() {
  document.getElementById('scanProgressTitle').textContent = 'Analyzing Security Posture...';
  document.getElementById('scanProgressSubtitle').textContent = 'Executing unauthenticated protocol probes against target...';
  Object.values(MILESTONE_ELEMENTS).forEach(id => {
    const el = document.getElementById(id);
    if (el) el.className = 'probe-pill';
  });
}

function updateScanProgressMilestone(stage, detail) {
  const titleEl = document.getElementById('scanProgressTitle');
  const subEl = document.getElementById('scanProgressSubtitle');

  if (titleEl && stage) titleEl.textContent = stage;
  if (subEl && detail) subEl.textContent = detail;

  const targetId = MILESTONE_ELEMENTS[stage];
  if (targetId) {
    const keys = Object.keys(MILESTONE_ELEMENTS);
    const currentIdx = keys.indexOf(stage);

    keys.forEach((k, idx) => {
      const el = document.getElementById(MILESTONE_ELEMENTS[k]);
      if (!el) return;
      if (idx < currentIdx) {
        el.className = 'probe-pill done';
      } else if (idx === currentIdx) {
        el.className = 'probe-pill active';
      } else {
        el.className = 'probe-pill';
      }
    });
  } else if (stage === 'Complete') {
    Object.values(MILESTONE_ELEMENTS).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.className = 'probe-pill done';
    });
  }
}

function showError(title, msg) {
  const banner = document.getElementById('errorBanner');
  document.getElementById('errorTitle').textContent = title;
  document.getElementById('errorMessage').textContent = msg;
  banner.classList.remove('hidden');
}

function showToast(msg) {
  const toast = document.getElementById('toastNotification');
  const text = document.getElementById('toastMessage');
  if (!toast || !text) return;
  text.textContent = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3000);
}

// Sticky Navigation Spy
function setupStickyNavSpy() {
  const sections = [
    'sec-overview',
    'sec-fix-first',
    'sec-categories',
    'sec-attack-surface',
    'sec-diagnostics',
    'sec-passed',
    'sec-history',
    'sec-not-assessed',
    'sec-telemetry'
  ];

  window.addEventListener('scroll', () => {
    const scrollPos = window.scrollY + 160;
    for (let i = sections.length - 1; i >= 0; i--) {
      const sec = document.getElementById(sections[i]);
      if (sec && sec.offsetTop <= scrollPos && !sec.classList.contains('hidden')) {
        document.querySelectorAll('.nav-tab').forEach(tab => {
          if (tab.dataset.sec === sections[i]) {
            tab.classList.add('active');
          } else {
            tab.classList.remove('active');
          }
        });
        break;
      }
    }
  });

  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      e.preventDefault();
      const secId = tab.dataset.sec;
      const targetSec = document.getElementById(secId);
      if (targetSec) {
        targetSec.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
}

// Main Render Function
function renderScanResult(data) {
  const card = data.score_card;
  const target = data.target;

  // 1. Top Header Metadata
  document.getElementById('resTargetUrl').textContent = target.normalized_url || target.host;
  document.getElementById('resTargetIps').textContent = `IP: ${(target.resolved_ips && target.resolved_ips.join(', ')) || 'N/A'}`;
  document.getElementById('resTargetPort').textContent = `${target.port} (${target.scheme ? target.scheme.toUpperCase() : 'HTTPS'})`;
  document.getElementById('resDuration').textContent = `${data.duration_seconds}s`;
  document.getElementById('resScanId').textContent = data.scan_id;
  document.getElementById('resTimestampBadge').textContent = `Scanned ${new Date(data.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

  // 2. Security Score Hero
  const score = card.overall_score;
  const grade = card.letter_grade;
  document.getElementById('scoreValue').textContent = score;

  const scoreExact = document.getElementById('scoreExactDisplay');
  if (scoreExact) {
    scoreExact.textContent = `Security Score: ${score} / 100`;
  }

  const gradeBadge = document.getElementById('gradeBadge');
  gradeBadge.textContent = `GRADE ${grade}`;

  // Gauge coloring
  let strokeColor = '#EF4444';
  let badgeBg = 'rgba(239, 68, 68, 0.15)';
  let badgeColor = '#EF4444';
  let verdictTitle = 'Elevated Risk — Immediate Attention Required';
  let verdictNarrative = `Expose detected severe perimeter exposures or missing fundamental controls on ${escapeHtml(target.host)}. Priority remediation is required to safeguard user sessions and traffic.`;

  if (score >= 90) {
    strokeColor = '#10B981';
    badgeBg = 'rgba(16, 185, 129, 0.15)';
    badgeColor = '#10B981';
    verdictTitle = 'Strong External Security Posture';
    verdictNarrative = `Your website demonstrates exemplary security posture across evaluated perimeter controls. Modern transport ciphers, hardened headers, and secure cookie scopes are active on the wire.`;
  } else if (score >= 75) {
    strokeColor = '#F59E0B';
    badgeBg = 'rgba(245, 158, 11, 0.15)';
    badgeColor = '#F59E0B';
    verdictTitle = 'Good — Recommended Hardening Opportunities';
    verdictNarrative = `Your website has a generally robust security foundation. Addressing a small number of configuration gaps will reinforce defenses against automated threat actors.`;
  } else if (score >= 60) {
    strokeColor = '#F97316';
    badgeBg = 'rgba(249, 115, 22, 0.15)';
    badgeColor = '#F97316';
    verdictTitle = 'Moderate Risk — Notable Perimeter Weaknesses';
    verdictNarrative = `Several key defensive layers are absent or misconfigured on ${escapeHtml(target.host)}. Attackers may exploit these gaps for session hijacking or credential interception.`;
  }

  gradeBadge.style.background = badgeBg;
  gradeBadge.style.color = badgeColor;
  gradeBadge.style.border = `1px solid ${strokeColor}`;

  // SVG Radial Animation (circumference = 314)
  const radialProgress = document.getElementById('radialProgress');
  radialProgress.style.stroke = strokeColor;
  const offset = 314 - (score / 100) * 314;
  setTimeout(() => {
    radialProgress.style.strokeDashoffset = offset;
  }, 100);

  // Executive Summary Text
  document.getElementById('execVerdictTitle').textContent = verdictTitle;
  document.getElementById('execSummaryText').textContent = verdictNarrative;

  // Counts
  const confirmedFindings = data.findings.filter(f => f.status === 'CONFIRMED');
  const passedFindings = data.findings.filter(f => f.status === 'OBSERVED');

  const criticalCount = confirmedFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = confirmedFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = confirmedFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = confirmedFindings.filter(f => f.severity === 'LOW').length;
  const passedCount = passedFindings.length;

  document.getElementById('countAll').textContent = confirmedFindings.length;
  document.getElementById('countCritical').textContent = criticalCount;
  document.getElementById('countHigh').textContent = highCount;
  document.getElementById('countMedium').textContent = mediumCount;
  document.getElementById('countLow').textContent = lowCount;
  document.getElementById('countPassed').textContent = passedCount;
  document.getElementById('passedHeaderCount').textContent = passedCount;

  // Navigation Pill Counts
  document.getElementById('navCountFixFirst').textContent = Math.min(3, confirmedFindings.length);
  document.getElementById('navCountDiagnostics').textContent = confirmedFindings.length;
  document.getElementById('navCountPassed').textContent = passedCount;

  // Executive summary focus list
  renderExecutiveKeyIssues(confirmedFindings);

  // Hero tally pill & Start Fixing button
  document.getElementById('heroIssueCount').textContent = confirmedFindings.length;
  document.getElementById('heroPassedCount').textContent = passedCount;
  document.getElementById('startFixingCount').textContent = `(${confirmedFindings.length} issues)`;

  // 3. Fix These First (Hero Action Area)
  renderFixTheseFirst(confirmedFindings, data.ai_prioritization);

  // 4. Security Categories (Horizontal progress meters)
  renderCategoryCards(card.category_scores);

  // 5. Attack Surface Discovery
  renderAttackSurface(data.attack_surface);

  // 6. Diagnostics (Grouped technical observations)
  renderDiagnostics();

  // 7. Passed Checks
  renderPassedChecks(passedFindings);

  // 8. Not Assessed Boundaries
  renderBoundaries(card.not_assessed_boundaries);

  // 9. Telemetry Details
  renderTelemetry(data);

  // Reveal results
  document.getElementById('resultsSection').classList.remove('hidden');
}

// Executive Summary Primary Focus Bullet Points
function renderExecutiveKeyIssues(confirmedFindings) {
  const container = document.getElementById('execKeyIssuesList');
  container.innerHTML = '';

  if (confirmedFindings.length === 0) {
    container.innerHTML = '<li>Zero critical or high-risk findings detected during external protocol inspection.</li>';
    return;
  }

  // Sort by severity
  const rank = { 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5 };
  const sorted = [...confirmedFindings].sort((a, b) => (rank[a.severity] || 9) - (rank[b.severity] || 9));
  const topThree = sorted.slice(0, 3);

  topThree.forEach(f => {
    const li = document.createElement('li');
    li.textContent = `${f.title} (${f.severity})`;
    container.appendChild(li);
  });
}

// Section: Fix These First (Hero Action Area)
function renderFixTheseFirst(confirmedFindings, aiPrioritization) {
  const container = document.getElementById('fixFirstContainer');
  const badge = document.getElementById('fixFirstCounterBadge');
  container.innerHTML = '';

  if (confirmedFindings.length === 0) {
    badge.textContent = '0 issues';
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--sev-passed); background: var(--sev-passed-bg); border-radius: var(--radius-md); border: 1px solid var(--sev-passed-border);">
        <strong>No Urgent Deficiencies Identified!</strong> Target demonstrates robust defensive posture across evaluated external controls.
      </div>
    `;
    return;
  }

  // Sort by risk
  const rank = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10 };
  const sorted = [...confirmedFindings].sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0));
  const topFindings = sorted.slice(0, 3);

  badge.textContent = `${topFindings.length} prioritized issues`;

  topFindings.forEach((f, idx) => {
    // Finding #1 expanded by default, subsequent compact
    const isExpanded = idx === 0;
    const card = renderSophisticatedFindingCard(f, {
      isPriority: true,
      priorityRank: idx + 1,
      isExpanded: isExpanded
    });
    container.appendChild(card);
  });
}

// Section: Security Categories (Horizontal Progress Bars)
function renderCategoryCards(categories) {
  const container = document.getElementById('categoryCardsContainer');
  container.innerHTML = '';

  for (const [name, cat] of Object.entries(categories)) {
    const card = document.createElement('div');
    card.className = `category-card ${currentCategoryFilter === name ? 'active' : ''}`;
    card.id = `cat-card-${name}`;

    let scoreColor = cat.score >= 90 ? 'var(--sev-passed)' : (cat.score >= 70 ? 'var(--sev-medium)' : 'var(--sev-critical)');
    const cleanName = name.replace(/_/g, ' ');

    card.innerHTML = `
      <div class="cat-header-row">
        <span class="cat-name">${escapeHtml(cleanName)}</span>
        <div class="cat-score" style="color: ${scoreColor}">
          ${cat.score} <span class="cat-score-scale">/100</span>
        </div>
      </div>
      <div class="cat-progress-track">
        <div class="cat-progress-fill" style="width: ${cat.score}%; background: ${scoreColor};"></div>
      </div>
      <div class="cat-meta-row">
        <span>Weight: ${cat.weight_percentage}% &bull; Issues: ${cat.confirmed_issues_count}</span>
        <span class="cat-action-link">View ${cat.confirmed_issues_count} findings &rarr;</span>
      </div>
    `;

    card.addEventListener('click', () => {
      filterByCategory(name);
    });

    container.appendChild(card);
  }
}

window.filterByCategory = function(catName) {
  currentCategoryFilter = catName;
  document.querySelectorAll('.category-card').forEach(c => c.classList.remove('active'));
  const activeCard = document.getElementById(`cat-card-${catName}`);
  if (activeCard) activeCard.classList.add('active');

  const indicator = document.getElementById('diagFilterIndicator');
  if (indicator) {
    indicator.textContent = `Filter: ${catName.replace(/_/g, ' ')}`;
  }

  renderDiagnostics();
  const diagSec = document.getElementById('sec-diagnostics');
  if (diagSec) diagSec.scrollIntoView({ behavior: 'smooth' });
};

window.resetCategoryFilter = function() {
  currentCategoryFilter = 'ALL';
  document.querySelectorAll('.category-card').forEach(c => c.classList.remove('active'));
  const indicator = document.getElementById('diagFilterIndicator');
  if (indicator) indicator.textContent = 'Filter: All Categories';
  renderDiagnostics();
};

// Section: Attack Surface Discovery
function renderAttackSurface(attackSurface) {
  if (!attackSurface) return;

  const pages = attackSurface.pages || [];
  const apis = attackSurface.apis || [];
  const scripts = attackSurface.scripts || [];
  const forms = attackSurface.forms || [];
  const deps = attackSurface.external_dependencies || [];
  const totalAssets = pages.length + apis.length + scripts.length + forms.length + deps.length;

  document.getElementById('attackSurfaceTotalBadge').textContent = `${totalAssets} public assets mapped`;
  document.getElementById('metricPages').querySelector('.metric-num').textContent = pages.length;
  document.getElementById('metricApis').querySelector('.metric-num').textContent = apis.length;
  document.getElementById('metricScripts').querySelector('.metric-num').textContent = scripts.length;
  document.getElementById('metricForms').querySelector('.metric-num').textContent = forms.length;
  document.getElementById('metricOrigins').querySelector('.metric-num').textContent = deps.length;

  document.getElementById('asTabPagesCount').textContent = pages.length;
  document.getElementById('asTabApisCount').textContent = apis.length;
  document.getElementById('asTabScriptsCount').textContent = scripts.length;
  document.getElementById('asTabFormsCount').textContent = forms.length;
  document.getElementById('asTabDepsCount').textContent = deps.length;

  renderAttackSurfaceContent();
}

function renderAttackSurfaceContent() {
  const container = document.getElementById('attackSurfaceContent');
  if (!currentScanResult || !currentScanResult.attack_surface) {
    container.innerHTML = '<div style="color:var(--text-dim); text-align:center; padding:20px;">No attack surface assets recorded.</div>';
    return;
  }

  const surf = currentScanResult.attack_surface;
  container.innerHTML = '';

  if (activeAttackSurfaceTab === 'pages') {
    const pages = surf.pages || [];
    if (pages.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:10px;">No pages discovered.</div>';
      return;
    }
    const list = document.createElement('div');
    list.className = 'as-list';
    pages.forEach(p => {
      const item = document.createElement('div');
      item.className = 'as-item';
      item.innerHTML = `
        <span>${escapeHtml(p.url || p.path)}</span>
        <span class="as-item-badge">${p.status_code || 200} ${p.has_forms ? '&bull; Has Forms' : ''}</span>
      `;
      list.appendChild(item);
    });
    container.appendChild(list);
  } else if (activeAttackSurfaceTab === 'apis') {
    const apis = surf.apis || [];
    if (apis.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:10px;">No exposed API endpoints discovered.</div>';
      return;
    }
    const list = document.createElement('div');
    list.className = 'as-list';
    apis.forEach(a => {
      const item = document.createElement('div');
      item.className = 'as-item';
      item.innerHTML = `
        <span>${escapeHtml(a.endpoint || a.path)}</span>
        <span class="as-item-badge">${a.method || 'GET'} ${a.is_authenticated ? 'AUTH' : 'PUBLIC'}</span>
      `;
      list.appendChild(item);
    });
    container.appendChild(list);
  } else if (activeAttackSurfaceTab === 'scripts') {
    const scripts = surf.scripts || [];
    if (scripts.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:10px;">No external or inline scripts captured.</div>';
      return;
    }
    const list = document.createElement('div');
    list.className = 'as-list';
    scripts.forEach(s => {
      const item = document.createElement('div');
      item.className = 'as-item';
      item.innerHTML = `
        <span>${escapeHtml(s.url || 'inline script')}</span>
        <span class="as-item-badge">${s.is_third_party ? '3RD PARTY' : 'FIRST PARTY'} ${s.has_integrity ? 'SRI' : 'NO SRI'}</span>
      `;
      list.appendChild(item);
    });
    container.appendChild(list);
  } else if (activeAttackSurfaceTab === 'forms') {
    const forms = surf.forms || [];
    if (forms.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:10px;">No HTML forms discovered.</div>';
      return;
    }
    const list = document.createElement('div');
    list.className = 'as-list';
    forms.forEach(f => {
      const item = document.createElement('div');
      item.className = 'as-item';
      item.innerHTML = `
        <span>Action: ${escapeHtml(f.action || '(self)')}</span>
        <span class="as-item-badge" style="${f.is_insecure_transport ? 'color:var(--sev-critical)' : ''}">
          ${f.method || 'POST'} ${f.has_password_field ? '&bull; Auth' : ''} ${f.is_insecure_transport ? '&bull; INSECURE HTTP' : 'HTTPS'}
        </span>
      `;
      list.appendChild(item);
    });
    container.appendChild(list);
  } else if (activeAttackSurfaceTab === 'dependencies') {
    const deps = surf.external_dependencies || [];
    if (deps.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:10px;">No third-party origin dependencies captured.</div>';
      return;
    }
    const list = document.createElement('div');
    list.className = 'as-list';
    deps.forEach(d => {
      const item = document.createElement('div');
      item.className = 'as-item';
      item.innerHTML = `
        <span>${escapeHtml(d.origin)}</span>
        <span class="as-item-badge">${d.resource_count || 1} resources (${escapeHtml(d.category || 'CDN')})</span>
      `;
      list.appendChild(item);
    });
    container.appendChild(list);
  } else if (activeAttackSurfaceTab === 'robots') {
    const robots = surf.robots_txt;
    const sitemaps = surf.sitemaps || [];
    container.innerHTML = `
      <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">
        <div><strong>Robots.txt:</strong> ${robots && robots.is_present ? 'Detected' : 'Not found'}</div>
        <div style="margin-top:6px;"><strong>Disallowed Paths:</strong> ${(robots && robots.disallowed_paths && robots.disallowed_paths.join(', ')) || 'None'}</div>
        <div style="margin-top:6px;"><strong>Sitemaps:</strong> ${sitemaps.join(', ') || 'None'}</div>
      </div>
    `;
  }
}

// Section: Diagnostics (Grouped by Domain)
function renderDiagnostics() {
  const container = document.getElementById('diagnosticsContainer');
  container.innerHTML = '';

  if (!currentScanResult) return;

  let findings = currentScanResult.findings.filter(f => f.status === 'CONFIRMED');

  // Severity filter
  if (currentSeverityFilter !== 'ALL') {
    findings = findings.filter(f => f.severity === currentSeverityFilter);
  }

  // Category filter
  if (currentCategoryFilter !== 'ALL') {
    findings = findings.filter(f => {
      const fCat = (f.category || '').toUpperCase().replace(/ /g, '_');
      const targetCat = currentCategoryFilter.toUpperCase().replace(/ /g, '_');
      return fCat === targetCat;
    });
  }

  // Keyword search filter
  if (searchQuery) {
    findings = findings.filter(f => {
      const title = (f.title || '').toLowerCase();
      const desc = (f.description || '').toLowerCase();
      const cat = (f.category || '').toLowerCase();
      const cwe = (f.cwe_id || '').toLowerCase();
      const owasp = (f.owasp_top10 || '').toLowerCase();
      const id = (f.id || '').toLowerCase();
      return title.includes(searchQuery) || desc.includes(searchQuery) || cat.includes(searchQuery) || cwe.includes(searchQuery) || owasp.includes(searchQuery) || id.includes(searchQuery);
    });
  }

  if (findings.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding: 40px; color: var(--text-dim); background: var(--bg-card); border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
        No diagnostic observations match the current filter criteria.
      </div>
    `;
    return;
  }

  // Group by category domain
  const groups = {};
  findings.forEach(f => {
    const domain = (f.category || 'General Security').replace(/_/g, ' ');
    if (!groups[domain]) groups[domain] = [];
    groups[domain].push(f);
  });

  for (const [domainName, domainFindings] of Object.entries(groups)) {
    const groupBlock = document.createElement('div');
    groupBlock.className = 'diag-domain-group';

    const groupHeader = document.createElement('div');
    groupHeader.className = 'diag-domain-header';
    groupHeader.innerHTML = `
      <span class="diag-domain-title">${escapeHtml(domainName)}</span>
      <span class="diag-domain-count">${domainFindings.length} finding${domainFindings.length === 1 ? '' : 's'}</span>
    `;

    const groupList = document.createElement('div');
    groupList.className = 'fix-first-container';
    groupList.style.marginTop = '8px';

    domainFindings.forEach(f => {
      const card = renderSophisticatedFindingCard(f, {
        isPriority: false,
        isExpanded: false
      });
      groupList.appendChild(card);
    });

    groupBlock.appendChild(groupHeader);
    groupBlock.appendChild(groupList);
    container.appendChild(groupBlock);
  }
}

// Sophisticated Reusable Finding Card Architecture
function renderSophisticatedFindingCard(f, options = {}) {
  const card = document.createElement('div');
  card.className = options.isPriority ? 'priority-finding-card finding-card' : 'finding-card';
  card.id = `finding-${f.id}`;

  const ev = f.evidence || {};
  let isExpanded = options.isExpanded !== undefined ? options.isExpanded : false;

  // Rank badge
  const rankBadgeHtml = options.isPriority ? `
    <span class="rank-badge font-mono">RANK #${options.priorityRank} FIX FIRST</span>
  ` : '';

  // OWASP / ASVS / CWE / CVE Badges
  const owaspTop10Html = f.owasp_top10 ? `
    <span>${escapeHtml(f.owasp_top10.split(' - ')[0])}</span>
    <span class="meta-sep">&bull;</span>
  ` : '';

  const owaspAsvsHtml = f.owasp_asvs ? `
    <span>ASVS ${escapeHtml(f.owasp_asvs)}</span>
    <span class="meta-sep">&bull;</span>
  ` : '';

  const cweHtml = f.cwe_id ? `
    <a href="https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-', '')}.html" target="_blank" rel="noopener">
      ${escapeHtml(f.cwe_id)}
    </a>
    <span class="meta-sep">&bull;</span>
  ` : '';

  const cveHtml = f.cve_id ? `
    <a href="https://nvd.nist.gov/vuln/detail/${f.cve_id}" target="_blank" rel="noopener">
      ${escapeHtml(f.cve_id)}
    </a>
    <span class="meta-sep">&bull;</span>
  ` : '';

  // CLI Verification snippet
  const verifyCmd = f.verification_command || (ev.command ? ev.command : '');
  const cliVerifyBoxHtml = verifyCmd ? `
    <div class="cli-verify-box" style="margin-top: 10px;">
      <span class="cli-verify-cmd">${escapeHtml(verifyCmd)}</span>
      <button class="btn btn-sm btn-outline" onclick="copyToClipboard('${escapeHtml(verifyCmd.replace(/'/g, "\\'"))}')">Copy Command</button>
    </div>
  ` : '';

  // Technical Evidence extraction
  let observedDetails = '';
  if (ev.response && ev.response.headers) {
    const headersStr = Object.entries(ev.response.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    observedDetails += `HTTP Response Status: ${ev.response.status_code || 200}\n${headersStr}\n\n`;
  }
  if (ev.raw_data) {
    observedDetails += JSON.stringify(ev.raw_data, null, 2);
  } else if (!observedDetails) {
    observedDetails = JSON.stringify(ev, null, 2);
  }

  // Simple View Pane
  const simplePaneHtml = `
    <div class="simple-explanation-pane" id="pane-simple-${f.id}">
      <p class="simple-lead">${escapeHtml(f.description)}</p>

      <div class="risk-explanation-box">
        <span class="risk-box-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--sev-medium)" stroke-width="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </span>
        <div>
          <div class="risk-box-title">SECURITY IMPACT &amp; THREAT VECTORS</div>
          <p class="risk-box-text">
            ${escapeHtml(f.impact_explanation || 'Leaves this website and visitors exposed to potential man-in-the-middle or spoofing attack vectors.')}
          </p>
          <div class="risk-honesty-note">
            Note: This observation reflects observable technical configuration; it does not by itself prove live weaponized exploitation.
          </div>
        </div>
      </div>

      <div class="remediation-action-box">
        <div class="remediation-box-title">RECOMMENDED REMEDIATION</div>
        <p class="remediation-box-text">${escapeHtml(f.remediation)}</p>
      </div>
    </div>
  `;

  // Developer Details Pane
  const devPaneHtml = `
    <div class="dev-details-pane hidden" id="pane-dev-${f.id}">
      <div class="dev-detail-row">
        <span class="dev-detail-label">1. Empirical Finding</span>
        <div class="dev-detail-body">${escapeHtml(f.description)}</div>
      </div>

      <div class="dev-detail-row">
        <span class="dev-detail-label">2. Security Impact &amp; Adversary Vectors</span>
        <div class="dev-detail-body">${escapeHtml(f.impact_explanation || 'Exposes application secrets, session tokens, or unencrypted assets.')}</div>
      </div>

      <div class="dev-detail-row">
        <span class="dev-detail-label">3. Recommended Technical Remediation</span>
        <div class="remediation-action-box" style="margin:0;">
          <div class="remediation-box-text">${escapeHtml(f.remediation)}</div>
        </div>
      </div>

      <div class="dev-detail-row">
        <span class="dev-detail-label">4. CLI Verification Method</span>
        ${cliVerifyBoxHtml}
      </div>

      <div class="dev-detail-row">
        <span class="dev-detail-label">5. Verifiable Technical Evidence (${escapeHtml(ev.type || 'RAW_SOCKET')})</span>
        <div class="evidence-block">
          <div class="evidence-block-header">
            <span class="evidence-tag">CAPTURED WIRE PROOF: ${escapeHtml(ev.summary || 'Empirical observation')}</span>
            <button class="copy-snippet-btn" onclick="copyToClipboard('${escapeHtml(observedDetails.replace(/'/g, "\\'").replace(/\n/g, "\\n"))}')">Copy Evidence</button>
          </div>
          <pre class="evidence-pre">${escapeHtml(observedDetails)}</pre>
        </div>
      </div>
    </div>
  `;

  card.innerHTML = `
    <!-- Top Bar -->
    <div class="finding-top-bar">
      <div class="finding-primary-meta">
        ${rankBadgeHtml}
        <span class="sev-pill ${f.severity}">${f.severity}</span>
        <span class="conf-pill ${f.confidence}" title="Confidence reflects direct wire verification certainty: ${f.confidence}">${f.confidence}</span>
        <span class="badge badge-outline">${f.status}</span>
      </div>
      <span class="finding-id-tag font-mono">${f.id}</span>
    </div>

    <!-- Finding Title -->
    <h3 class="finding-title">${escapeHtml(f.title)}</h3>

    <!-- Secondary Metadata -->
    <div class="finding-secondary-meta font-mono">
      ${owaspTop10Html}
      ${owaspAsvsHtml}
      ${cweHtml}
      ${cveHtml}
      <span>Category: ${escapeHtml((f.category || 'General').replace(/_/g, ' '))}</span>
    </div>

    <!-- Body Container (Collapsible) -->
    <div class="finding-collapsible-body ${isExpanded ? '' : 'hidden'}" id="body-${f.id}">
      <!-- Control Bar: Dual View & Actions -->
      <div class="finding-control-bar">
        <div class="dual-view-toggle">
          <button class="dual-view-btn active" onclick="switchFindingView('${f.id}', 'simple')">Simple explanation</button>
          <button class="dual-view-btn" onclick="switchFindingView('${f.id}', 'dev')">Developer details</button>
        </div>

        <div class="finding-actions">
          <button class="btn btn-sm btn-outline btn-ai-help" id="btn-ai-${f.id}" onclick="toggleAiHelp('${f.id}')" title="Consult contextual AI security intelligence on this finding">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:5px;"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>AI Analysis
          </button>
          <div id="verify-action-${f.id}">
            ${f.status !== 'FIXED' ? `
              <button class="btn-verify" id="btn-verify-${f.id}" onclick="triggerVerifyFix('${f.id}')" title="Re-check this finding on target host with fresh wire proof">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:5px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Verify Fix
              </button>
            ` : `
              <span class="badge badge-verified"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>Fix Verified</span>
            `}
          </div>
        </div>
      </div>

      <!-- Verification Feedback Banner -->
      <div id="verify-feedback-${f.id}" class="verify-feedback-banner hidden"></div>

      <!-- Panes -->
      ${simplePaneHtml}
      ${devPaneHtml}

      <!-- Contextual AI Assistant Panel -->
      <div id="ai-help-pane-${f.id}" class="ai-help-pane hidden"></div>
    </div>

    <!-- Expand/Collapse Toggle Footer for Compact Cards -->
    <div style="display: flex; justify-content: flex-end; margin-top: 10px;">
      <button class="btn-toggle-details" onclick="toggleFindingExpansion('${f.id}')" id="btn-toggle-${f.id}">
        <span>${isExpanded ? 'Hide details &uarr;' : 'View details &rarr;'}</span>
      </button>
    </div>
  `;

  return card;
}

window.toggleFindingExpansion = function(findingId) {
  const body = document.getElementById(`body-${findingId}`);
  const btn = document.getElementById(`btn-toggle-${findingId}`);
  if (!body || !btn) return;

  const isNowHidden = !body.classList.contains('hidden');
  if (isNowHidden) {
    body.classList.add('hidden');
    btn.innerHTML = '<span>View details &rarr;</span>';
  } else {
    body.classList.remove('hidden');
    btn.innerHTML = '<span>Hide details &uarr;</span>';
  }
};

window.switchFindingView = function(findingId, mode) {
  const card = document.getElementById(`finding-${findingId}`);
  if (!card) return;

  const buttons = card.querySelectorAll('.dual-view-btn');
  const simplePane = document.getElementById(`pane-simple-${findingId}`);
  const devPane = document.getElementById(`pane-dev-${findingId}`);

  if (mode === 'simple') {
    buttons[0].classList.add('active');
    buttons[1].classList.remove('active');
    if (simplePane) simplePane.classList.remove('hidden');
    if (devPane) devPane.classList.add('hidden');
  } else {
    buttons[0].classList.remove('active');
    buttons[1].classList.add('active');
    if (simplePane) simplePane.classList.add('hidden');
    if (devPane) devPane.classList.remove('hidden');
  }
};

// Contextual AI Help Panel
window.toggleAiHelp = async function(findingId) {
  const pane = document.getElementById(`ai-help-pane-${findingId}`);
  const btn = document.getElementById(`btn-ai-${findingId}`);
  if (!pane || !btn) return;

  if (!pane.classList.contains('hidden')) {
    pane.classList.add('hidden');
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:5px;"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>AI Analysis';
    return;
  }

  const finding = currentScanResult && currentScanResult.findings.find(x => x.id === findingId);

  // Render contextual AI panel with prompt chips
  pane.innerHTML = `
    <div class="ai-pane-header">
      <div class="ai-pane-title">
        <span>CONTEXTUAL SECURITY INTELLIGENCE</span>
      </div>
      <button class="btn btn-sm btn-outline" style="padding: 2px 8px; font-size: 0.72rem;" onclick="toggleAiHelp('${findingId}')">Close</button>
    </div>
    
    <p style="font-size:0.82rem; color:var(--text-muted); margin-bottom:10px;">
      Analyzing findings context for <strong>${escapeHtml((finding && finding.title) || findingId)}</strong>. Select a topic for authoritative guidance:
    </p>

    <div class="ai-prompts-bar">
      <button class="ai-prompt-chip" onclick="askAiQuestion('${findingId}', 'Explain in simpler terms')">Explain in simpler terms</button>
      <button class="ai-prompt-chip" onclick="askAiQuestion('${findingId}', 'Why is this risky?')">Why is this risky?</button>
      <button class="ai-prompt-chip" onclick="askAiQuestion('${findingId}', 'How do I fix this?')">How do I fix this?</button>
      <button class="ai-prompt-chip" onclick="askAiQuestion('${findingId}', 'Show developer guidance')">Show developer guidance</button>
      <button class="ai-prompt-chip" onclick="askAiQuestion('${findingId}', 'What could an attacker do?')">What could an attacker do?</button>
    </div>

    <div id="ai-response-area-${findingId}">
      <div style="font-size:0.82rem; color:#D8B4FE; padding:10px; background: rgba(192, 132, 252, 0.05); border-radius: 6px;">
        Click any question above to generate grounded, evidence-backed security insights.
      </div>
    </div>
  `;

  pane.classList.remove('hidden');
  btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:5px;"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Close AI Analysis';
};

window.askAiQuestion = async function(findingId, questionText) {
  const respArea = document.getElementById(`ai-response-area-${findingId}`);
  if (!respArea) return;

  respArea.innerHTML = `
    <div style="font-size:0.82rem; color:#D8B4FE; padding:10px; background: rgba(192, 132, 252, 0.05); border-radius: 6px;">
      Consulting AI security engine for "${escapeHtml(questionText)}"...
    </div>
  `;

  const finding = currentScanResult && currentScanResult.findings.find(x => x.id === findingId);

  try {
    const scanId = currentScanResult.scan_id;
    let report = finding && finding.ai_intelligence;

    if (!report) {
      const res = await fetch(`/api/v1/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/intelligence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (!res.ok) throw new Error('AI assistant failed to generate report');
      report = await res.json();
      if (finding) finding.ai_intelligence = report;
    }

    respArea.innerHTML = renderAiStructuredResponse(report, questionText, finding);
  } catch (err) {
    respArea.innerHTML = `
      <div class="feedback-status-row" style="font-size:0.82rem; color:#f87171; padding:10px; background: rgba(239, 68, 68, 0.08); border-radius: 6px; border: 1px solid rgba(239, 68, 68, 0.2);">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>${escapeHtml(err.message)}</span>
      </div>
    `;
  }
};

function renderAiStructuredResponse(ai, prompt, finding) {
  return `
    <div class="ai-reasoning-grid">
      <div class="ai-reason-item">
        <span class="ai-reason-title">Observation &amp; Meaning</span>
        <p class="ai-reason-body">${escapeHtml(ai.security_meaning || ai.explanation || finding.description)}</p>
      </div>
      <div class="ai-reason-item">
        <span class="ai-reason-title">Contextual Risk</span>
        <p class="ai-reason-body">${escapeHtml(ai.impact || ai.contextual_impact || finding.impact_explanation || 'Leaves perimeter exposed to untrusted requests.')}</p>
      </div>
      <div class="ai-reason-item">
        <span class="ai-reason-title">Authoritative Real-World Context</span>
        <p class="ai-reason-body">${escapeHtml(ai.real_world_context || 'Documented in industry best practice standards including OWASP and ASVS.')}</p>
      </div>
      <div class="ai-reason-item">
        <span class="ai-reason-title">Developer Guidance &amp; Remediation</span>
        <p class="ai-reason-body">${escapeHtml(ai.recommendation || finding.remediation)}</p>
      </div>
    </div>
  `;
}

// Live Empirical Verification Interaction (Phase 15)
window.triggerVerifyFix = async function(findingId) {
  if (!currentScanResult) return;
  const btn = document.getElementById(`btn-verify-${findingId}`);
  const feedback = document.getElementById(`verify-feedback-${findingId}`);
  const actionContainer = document.getElementById(`verify-action-${findingId}`);

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="inline-spinner"></span> Verifying on wire...';
  }

  try {
    const res = await fetch(`/api/v1/scans/${encodeURIComponent(currentScanResult.scan_id)}/findings/${encodeURIComponent(findingId)}/verify`, {
      method: 'POST'
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Verification request failed.');
    }

    if (feedback) {
      feedback.classList.remove('hidden');
      if (data.status === 'FIXED') {
        feedback.className = 'verify-feedback-banner verify-success';
        feedback.innerHTML = `
          <div class="feedback-status-row">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--sev-passed)" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
            <strong>Fix Confirmed by Wire Verification</strong>
          </div>
          <p style="margin: 4px 0 0;">${escapeHtml(data.message)}</p>
          <div style="margin-top: 6px; font-size: 0.85rem; font-family: var(--font-mono);">
            Security Score: <strong>${data.score_before}</strong> &rarr; <strong style="color:var(--sev-passed)">${data.score_after}</strong> (+${data.score_delta} pts)
          </div>
        `;
        if (actionContainer) {
          actionContainer.innerHTML = `<span class="badge badge-verified"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>Fix Verified</span>`;
        }

        // Update score display dynamically on hero card
        if (currentScanResult.score_card) {
          currentScanResult.score_card.overall_score = data.score_after;
          const scoreEl = document.getElementById('scoreValue');
          if (scoreEl) scoreEl.textContent = data.score_after;
          const fg = document.getElementById('radialProgress');
          if (fg) {
            const circumference = 314;
            const offset = circumference - (data.score_after / 100) * circumference;
            fg.style.strokeDashoffset = offset;
          }
          const exactDisplay = document.getElementById('scoreExactDisplay');
          if (exactDisplay) {
            exactDisplay.textContent = `Security Score: ${data.score_after} / 100`;
          }
        }

        // Update finding status badge in card
        const card = document.getElementById(`finding-${findingId}`);
        if (card) {
          const statBadge = card.querySelector('.badge-outline');
          if (statBadge) {
            statBadge.textContent = 'FIXED';
            statBadge.style.color = '#34D399';
            statBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
          }
        }

        // Update in-memory finding
        const tf = currentScanResult.findings.find(f => f.id === findingId);
        if (tf) {
          tf.status = 'FIXED';
          if (data.after_evidence) tf.evidence = data.after_evidence;
        }

        // Re-fetch continuous monitoring history & diff
        fetchTargetHistoryAndDiff(currentScanResult.target.host, currentScanResult.scan_id);
      } else {
        feedback.className = 'verify-feedback-banner verify-failed';
        feedback.innerHTML = `
          <div class="feedback-status-row">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--sev-high)" stroke-width="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <strong>Finding Persists on Target</strong>
          </div>
          <p style="margin: 4px 0 0;">${escapeHtml(data.message)}</p>
        `;
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:5px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Retry Verify Fix';
        }
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.classList.remove('hidden');
      feedback.className = 'verify-feedback-banner verify-failed';
      feedback.innerHTML = `<strong>Verification Error:</strong> ${escapeHtml(err.message)}`;
    }
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:5px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Verify Fix';
    }
  }
};

// Section: Passed Checks
function renderPassedChecks(passedFindings) {
  const container = document.getElementById('passedContainer');
  container.innerHTML = '';

  if (passedFindings.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 20px; text-align: center; color: var(--text-dim);">
        No passing controls recorded during this assessment run.
      </div>
    `;
    return;
  }

  passedFindings.forEach(f => {
    const card = document.createElement('div');
    card.className = 'passed-card';
    card.innerHTML = `
      <div class="passed-icon">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <div>
        <div class="passed-title">${escapeHtml(f.title)}</div>
        <div class="passed-desc">${escapeHtml(f.description)}</div>
      </div>
    `;
    container.appendChild(card);
  });
}

// Section: Not Assessed Boundaries
function renderBoundaries(boundaries) {
  const container = document.getElementById('boundaryList');
  container.innerHTML = '';

  (boundaries || []).forEach(b => {
    const item = document.createElement('div');
    item.className = 'boundary-item';
    item.innerHTML = `
      <h4>${escapeHtml(b.area)}</h4>
      <div class="boundary-reason">Boundary: ${escapeHtml(b.reason)}</div>
      <div class="boundary-expl">${escapeHtml(b.explanation)}</div>
    `;
    container.appendChild(item);
  });
}

// Section: Telemetry Details
function renderTelemetry(data) {
  const grid = document.getElementById('telemetryGrid');
  if (!grid) return;

  grid.innerHTML = `
    <div class="telemetry-item">
      <span class="telemetry-label">Scanner Engine</span>
      <span class="telemetry-val">Expose v0.1.0-beta</span>
    </div>
    <div class="telemetry-item">
      <span class="telemetry-label">Rules Version</span>
      <span class="telemetry-val">rules-v2026.09.10</span>
    </div>
    <div class="telemetry-item">
      <span class="telemetry-label">Scorecard Engine</span>
      <span class="telemetry-val">v${(data.score_card && data.score_card.score_version) || '1.0'}</span>
    </div>
    <div class="telemetry-item">
      <span class="telemetry-label">Target Scheme &amp; Port</span>
      <span class="telemetry-val">${data.target.scheme.toUpperCase()} / ${data.target.port}</span>
    </div>
    <div class="telemetry-item">
      <span class="telemetry-label">Total Execution Time</span>
      <span class="telemetry-val">${data.duration_seconds}s</span>
    </div>
    <div class="telemetry-item">
      <span class="telemetry-label">Scan ID</span>
      <span class="telemetry-val font-mono">${data.scan_id}</span>
    </div>
  `;
}

// Score Methodology Modal Details
function renderScoreMethodology() {
  const grid = document.getElementById('modalWeightsGrid');
  if (!grid || !currentScanResult || !currentScanResult.score_card) return;

  const cats = currentScanResult.score_card.category_scores || {};
  grid.innerHTML = '';

  for (const [name, cat] of Object.entries(cats)) {
    const row = document.createElement('div');
    row.className = 'weight-row';
    row.innerHTML = `
      <span class="weight-cat">${escapeHtml(name.replace(/_/g, ' '))}</span>
      <span class="weight-pct">${cat.weight_percentage}%</span>
    `;
    grid.appendChild(row);
  }
}

// Continuous Monitoring: Fetch Target History & Diff (Phase 16)
async function fetchTargetHistoryAndDiff(targetHost, scanId) {
  const historySection = document.getElementById('sec-history');
  const container = document.getElementById('historyDiffContainer');
  if (!historySection || !container) return;

  try {
    const [histRes, diffRes] = await Promise.all([
      fetch(`/api/v1/targets/${encodeURIComponent(targetHost)}/history`),
      fetch(`/api/v1/scans/${encodeURIComponent(scanId)}/diff`)
    ]);

    if (!histRes.ok || !diffRes.ok) return;

    const history = await histRes.json();
    const diff = await diffRes.json();

    historySection.classList.remove('hidden');

    if (history.length <= 1 && (!diff.previous_scan_id)) {
      container.innerHTML = `
        <div class="history-card">
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <span class="diff-badge diff-fixed">Baseline Scan #1</span>
            <span style="color: var(--text-dim); font-size: 0.85rem;">Continuous monitoring active. Subsequent scans of <strong>${escapeHtml(targetHost)}</strong> will record verified posture deltas (+ NEW, RESOLVED, CHANGED).</span>
          </div>
        </div>
      `;
      return;
    }

    let timelineHtml = history.map((h, i) => `
      <div class="history-step ${h.scan_id === scanId ? 'active' : ''}">
        <span class="step-num">Scan #${i + 1}</span>
        <span class="step-score ${h.score >= 80 ? 'score-good' : h.score >= 60 ? 'score-warn' : 'score-bad'}">${h.score}/100 (${h.letter_grade})</span>
        <span class="step-date">${new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      </div>
    `).join('<span class="timeline-arrow">&rarr;</span>');

    let diffBadgesHtml = `
      <div class="diff-summary-badges">
        <span class="diff-badge diff-new">+ ${diff.new_findings.length} NEW</span>
        <span class="diff-badge diff-fixed"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="vertical-align: -1px; margin-right: 3px;"><polyline points="20 6 9 17 4 12"/></svg>${diff.fixed_findings.length} RESOLVED</span>
        <span class="diff-badge diff-changed">~ ${diff.changed_findings.length} CHANGED</span>
        <span class="diff-badge diff-delta" style="color:${diff.score_delta >= 0 ? 'var(--sev-passed)' : 'var(--sev-critical)'}">
          Score Delta: ${diff.score_delta >= 0 ? '+' : ''}${diff.score_delta} pts
        </span>
      </div>
    `;

    container.innerHTML = `
      <div class="history-card">
        <div class="history-timeline-bar">${timelineHtml}</div>
        ${diffBadgesHtml}
        <div class="diff-summary-text">${escapeHtml(diff.summary)}</div>
      </div>
    `;

    container.innerHTML = `
      <div class="history-card">
        <div class="history-timeline-bar">${timelineHtml}</div>
        ${diffBadgesHtml}
        <div class="diff-summary-text">${escapeHtml(diff.summary)}</div>
      </div>
    `;
  } catch (err) {
    console.warn('Continuous monitoring history fetch error:', err);
  }
}

// Global Copy Helper
window.copyToClipboard = function(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!');
  }).catch(() => {
    prompt('Copy to clipboard: Ctrl+C, Enter', text);
  });
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

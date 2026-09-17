/**
 * SecureDeploy — Frontend Application Logic
 * Handles tab navigation, scan submission, progress polling, results rendering,
 * report downloads, and scan history.
 */

(function () {
    'use strict';

    // ========================================================================
    // State
    // ========================================================================
    let currentScanId = null;
    let pollInterval = null;
    let currentSourceType = 'git_url';
    let currentFilter = 'all';
    let allFindings = [];

    // ========================================================================
    // DOM References
    // ========================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const panels = {
        submit: $('#panel-submit'),
        progress: $('#panel-progress'),
        results: $('#panel-results'),
        history: $('#panel-history'),
    };

    const navBtns = {
        submit: $('#nav-submit'),
        progress: $('#nav-progress'),
        results: $('#nav-results'),
        history: $('#nav-history'),
    };

    // ========================================================================
    // Tab Navigation
    // ========================================================================
    function switchTab(tabName) {
        // Update panels
        Object.entries(panels).forEach(([key, panel]) => {
            panel.classList.toggle('active', key === tabName);
        });

        // Update nav buttons
        Object.entries(navBtns).forEach(([key, btn]) => {
            btn.classList.toggle('active', key === tabName);
        });

        // Load history when switching to that tab
        if (tabName === 'history') {
            loadHistory();
        }
    }

    $$('.nav-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            if (tab) switchTab(tab);
        });
    });

    // ========================================================================
    // Source Type Tabs
    // ========================================================================
    $$('.source-tab').forEach((tab) => {
        tab.addEventListener('click', () => {
            currentSourceType = tab.dataset.source;

            // Toggle active state
            $$('.source-tab').forEach((t) => t.classList.remove('active'));
            tab.classList.add('active');

            // Show/hide input areas
            $$('.input-area').forEach((area) => {
                area.classList.toggle('hidden', area.id !== `input-${currentSourceType}`);
            });
        });
    });

    // ========================================================================
    // Drag & Drop Zone
    // ========================================================================
    const dropZone = $('#drop-zone');
    const fileInput = $('#zip-file-input');
    const fileNameDisplay = $('#selected-file-name');

    if (dropZone) {
        ['dragenter', 'dragover'].forEach((evt) => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach((evt) => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                fileNameDisplay.textContent = `Selected: ${files[0].name}`;
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileNameDisplay.textContent = `Selected: ${fileInput.files[0].name}`;
            }
        });
    }

    // ========================================================================
    // Submit Scan
    // ========================================================================
    const startBtn = $('#start-scan-btn');
    const submitError = $('#submit-error');

    startBtn.addEventListener('click', async () => {
        submitError.classList.add('hidden');
        submitError.textContent = '';

        const sourceValue = getSourceValue();
        if (!sourceValue) {
            showSubmitError('Please provide a repository source.');
            return;
        }

        startBtn.classList.add('btn--loading');
        startBtn.disabled = true;

        try {
            let response;

            if (currentSourceType === 'zip_upload') {
                const formData = new FormData();
                formData.append('source_type', 'zip_upload');
                formData.append('source_value', fileInput.files[0].name);
                formData.append('file', fileInput.files[0]);

                response = await fetch('/api/scan', {
                    method: 'POST',
                    body: formData,
                });
            } else {
                response = await fetch('/api/scan/json', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        source_type: currentSourceType,
                        source_value: sourceValue,
                    }),
                });
            }

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err.detail || `Server error: ${response.status}`);
            }

            const data = await response.json();
            currentScanId = data.scan_id;

            // Show progress tab
            navBtns.progress.style.display = '';
            switchTab('progress');
            $('#progress-scan-id').textContent = `Scan ID: ${currentScanId}`;
            startPolling();

        } catch (err) {
            showSubmitError(err.message);
        } finally {
            startBtn.classList.remove('btn--loading');
            startBtn.disabled = false;
        }
    });

    function getSourceValue() {
        switch (currentSourceType) {
            case 'git_url':
                return $('#git-url-input').value.trim();
            case 'zip_upload':
                return fileInput.files.length > 0 ? fileInput.files[0].name : '';
            case 'local_path':
                return $('#local-path-input').value.trim();
            default:
                return '';
        }
    }

    function showSubmitError(msg) {
        submitError.textContent = msg;
        submitError.classList.remove('hidden');
    }

    // ========================================================================
    // Progress Polling
    // ========================================================================
    const PHASE_ORDER = ['queued', 'cloning', 'scanning', 'analyzing', 'complete'];
    const PHASE_PROGRESS = { queued: 5, cloning: 20, scanning: 50, analyzing: 80, complete: 100 };

    function startPolling() {
        updateProgress('queued', 'Initializing...');

        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollStatus, 1000);
    }

    async function pollStatus() {
        if (!currentScanId) return;

        try {
            const resp = await fetch(`/api/scan/${currentScanId}/status`);
            if (!resp.ok) return;

            const data = await resp.json();
            updateProgress(data.status, data.phase_message);

            if (data.status === 'complete') {
                clearInterval(pollInterval);
                pollInterval = null;
                await loadResults();
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                pollInterval = null;
                updateProgress('failed', data.phase_message || 'Scan failed');
            }
        } catch (err) {
            console.error('Poll error:', err);
        }
    }

    function updateProgress(status, message) {
        const pct = PHASE_PROGRESS[status] || 0;
        const circumference = 2 * Math.PI * 52; // r=52

        // Update ring
        const circle = $('#progress-circle');
        if (circle) {
            const offset = circumference - (pct / 100) * circumference;
            circle.style.strokeDasharray = circumference;
            circle.style.strokeDashoffset = offset;
            // Add gradient def if not present
            const svg = circle.closest('svg');
            if (svg && !svg.querySelector('#prog-grad')) {
                const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
                defs.innerHTML = `
                    <linearGradient id="prog-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#7c3aed"/>
                        <stop offset="100%" stop-color="#06b6d4"/>
                    </linearGradient>`;
                svg.prepend(defs);
                circle.style.stroke = 'url(#prog-grad)';
            }
        }

        $('#progress-percent').textContent = `${pct}%`;
        $('#progress-message').textContent = message;

        // Update phase dots
        const currentIdx = PHASE_ORDER.indexOf(status);
        $$('.phase').forEach((el) => {
            const phaseIdx = PHASE_ORDER.indexOf(el.dataset.phase);
            el.classList.remove('active', 'done');
            if (phaseIdx < currentIdx) el.classList.add('done');
            else if (phaseIdx === currentIdx) el.classList.add('active');
        });
    }

    // ========================================================================
    // Load & Render Results
    // ========================================================================
    async function loadResults() {
        if (!currentScanId) return;

        try {
            const resp = await fetch(`/api/scan/${currentScanId}/results`);
            if (!resp.ok) return;

            const data = await resp.json();
            allFindings = data.findings || [];

            // Switch to results tab
            navBtns.results.style.display = '';
            switchTab('results');

            // Render summary
            const s = data.summary || {};
            $('#results-scan-info').textContent =
                `${data.source_type} — ${data.source_value} | Scan ID: ${data.scan_id}`;
            $('#summary-total').textContent = s.total_findings || 0;
            $('#summary-critical').textContent = s.critical || 0;
            $('#summary-high').textContent = s.high || 0;
            $('#summary-medium').textContent = s.medium || 0;
            $('#summary-low').textContent = s.low || 0;

            // Animate counter values
            animateCounters();

            // AI Analysis
            if (data.ai_analysis) {
                $('#ai-analysis-section').classList.remove('hidden');
                $('#ai-analysis-content').textContent = data.ai_analysis;
            } else {
                $('#ai-analysis-section').classList.add('hidden');
            }

            // Render findings
            renderFindings(allFindings);

            // Show/hide empty state
            if (allFindings.length === 0) {
                $('#no-findings').classList.remove('hidden');
                $('#filter-bar').classList.add('hidden');
            } else {
                $('#no-findings').classList.add('hidden');
                $('#filter-bar').classList.remove('hidden');
            }

        } catch (err) {
            console.error('Failed to load results:', err);
        }
    }

    function renderFindings(findings) {
        const list = $('#findings-list');
        list.innerHTML = '';

        findings.forEach((f, idx) => {
            const card = document.createElement('div');
            card.className = 'finding-card';
            card.dataset.severity = f.severity;
            card.dataset.category = f.category;
            card.style.animationDelay = `${idx * 0.03}s`;

            const catLabel = {
                code_pattern: 'Code',
                dependency: 'Dependency',
                secret: 'Secret',
            }[f.category] || f.category;

            card.innerHTML = `
                <div class="finding-card__header">
                    <div class="finding-card__main">
                        <div class="finding-card__title">${escapeHtml(f.title)}</div>
                        <div class="finding-card__meta">
                            <span>🔧 ${escapeHtml(f.scanner)}</span>
                            ${f.cwe ? `<span>${escapeHtml(f.cwe)}</span>` : ''}
                        </div>
                    </div>
                    <div class="finding-card__badges">
                        <span class="sev-badge sev-badge--${f.severity}">${f.severity}</span>
                        <span class="cat-badge">${catLabel}</span>
                        ${f.attack_type ? `<span class="attack-badge">🛡️ ${escapeHtml(f.attack_type)}</span>` : ''}
                        <span class="finding-card__chevron">▼</span>
                    </div>
                </div>
                <div class="finding-card__body">
                    ${f.file_path ? `
                    <div class="finding-card__location">
                        <strong>📍 Location:</strong> <code>${escapeHtml(f.file_path)}${f.line_start ? ` : line ${f.line_start}` : ''}</code>
                    </div>
                    ` : ''}
                    <p class="finding-card__desc">${escapeHtml(f.description)}</p>
                    ${f.risk_explanation ? `
                    <div class="finding-card__risk">
                        <strong>⚠️ Why is this a risk?</strong>
                        <p>${escapeHtml(f.risk_explanation)}</p>
                    </div>
                    ` : ''}
                    ${f.code_snippet ? `<pre class="finding-card__code">${escapeHtml(f.code_snippet)}</pre>` : ''}
                    ${f.fix_suggestion ? `
                        <div class="finding-card__fix">
                            <span class="finding-card__fix-icon">💡</span>
                            <span class="finding-card__fix-text">${escapeHtml(f.fix_suggestion)}</span>
                        </div>
                    ` : ''}
                    ${f.reference_urls && f.reference_urls.length > 0 ? `
                        <div class="finding-card__refs">
                            ${f.reference_urls.map((u) => `<a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(u)}</a>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;

            // Toggle expand on header click
            const header = card.querySelector('.finding-card__header');
            header.addEventListener('click', () => {
                card.classList.toggle('expanded');
            });

            list.appendChild(card);
        });
    }

    function animateCounters() {
        $$('.summary-card__value').forEach((el) => {
            const target = parseInt(el.textContent, 10) || 0;
            if (target === 0) return;
            let current = 0;
            const increment = Math.max(1, Math.ceil(target / 20));
            const timer = setInterval(() => {
                current += increment;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                el.textContent = current;
            }, 30);
        });
    }

    // ========================================================================
    // Filters
    // ========================================================================
    $$('.filter-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            currentFilter = btn.dataset.filter;
            $$('.filter-btn').forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');

            let filtered = allFindings;
            if (currentFilter !== 'all') {
                filtered = allFindings.filter(
                    (f) => f.severity === currentFilter || f.category === currentFilter
                );
            }
            renderFindings(filtered);
        });
    });

    // ========================================================================
    // Downloads
    // ========================================================================
    $('#download-md-btn').addEventListener('click', () => {
        if (currentScanId) {
            window.open(`/api/scan/${currentScanId}/report/markdown`, '_blank');
        }
    });

    $('#download-json-btn').addEventListener('click', () => {
        if (currentScanId) {
            window.open(`/api/scan/${currentScanId}/report/json`, '_blank');
        }
    });

    $('#new-scan-btn').addEventListener('click', () => {
        switchTab('submit');
    });

    // ========================================================================
    // History
    // ========================================================================
    async function loadHistory() {
        try {
            const resp = await fetch('/api/history');
            if (!resp.ok) return;

            const data = await resp.json();
            const list = $('#history-list');
            const empty = $('#no-history');

            if (!data.history || data.history.length === 0) {
                list.innerHTML = '';
                empty.classList.remove('hidden');
                return;
            }

            empty.classList.add('hidden');
            list.innerHTML = data.history
                .map((h) => {
                    const statusClass = h.status === 'complete' ? 'complete' : 'failed';
                    const date = h.started_at
                        ? new Date(h.started_at).toLocaleString()
                        : 'Unknown';

                    return `
                        <div class="history-item">
                            <div class="history-item__info">
                                <div class="history-item__source">${escapeHtml(h.source_value)}</div>
                                <div class="history-item__date">${escapeHtml(date)} · ${escapeHtml(h.source_type)}</div>
                            </div>
                            <div class="history-item__stats">
                                <span class="history-item__count history-item__count--total">${h.total_findings} findings</span>
                                ${h.critical > 0 ? `<span class="history-item__count history-item__count--critical">${h.critical} critical</span>` : ''}
                                ${h.high > 0 ? `<span class="history-item__count history-item__count--high">${h.high} high</span>` : ''}
                                <span class="status-badge status-badge--${statusClass}">${h.status}</span>
                            </div>
                        </div>
                    `;
                })
                .join('');
        } catch (err) {
            console.error('Failed to load history:', err);
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    // ========================================================================
    // Init
    // ========================================================================
    loadHistory();

})();

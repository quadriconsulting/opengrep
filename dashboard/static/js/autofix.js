/**
 * DevSecure Dashboard - Auto-Fix Management JavaScript
 * Manage AI-powered auto-fixes and PR tracking
 */

class AutoFixManager {
    constructor() {
        this.activeFixes = [];
        this.pullRequests = [];
        this.fixHistory = [];
        this.metrics = {
            fixes_applied: 0,
            fixes_pending: 0,
            active_prs: 0,
            merged_prs: 0,
            success_rate: 0,
            ai_confidence: 0
        };
        
        this.charts = {};
        this.refreshInterval = null;
        
        this.initializeEventListeners();
        this.loadData();
        this.startAutoRefresh();
    }
    
    /**
     * Initialize event listeners
     */
    initializeEventListeners() {
        // Tab switching
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                const target = e.target.getAttribute('data-bs-target');
                this.onTabSwitch(target);
            });
        });
        
        // Refresh button
        document.getElementById('refresh-autofix-btn').addEventListener('click', () => {
            this.loadData();
        });
        
        // Batch fix button
        document.getElementById('batch-fix-btn').addEventListener('click', () => {
            this.showBatchFixModal();
        });
        
        // Active fixes controls
        document.getElementById('active-status-filter').addEventListener('change', (e) => {
            this.filterActiveFixes(e.target.value);
        });
        
        document.getElementById('cancel-all-btn').addEventListener('click', () => {
            this.cancelAllFixes();
        });
        
        // PR management controls
        document.getElementById('pr-status-filter').addEventListener('change', (e) => {
            this.filterPullRequests(e.target.value);
        });
        
        document.getElementById('sync-prs-btn').addEventListener('click', () => {
            this.syncPullRequests();
        });
        
        // History controls
        document.getElementById('history-date-from').addEventListener('change', () => {
            this.filterHistory();
        });
        
        document.getElementById('history-date-to').addEventListener('change', () => {
            this.filterHistory();
        });
        
        document.getElementById('history-outcome-filter').addEventListener('change', () => {
            this.filterHistory();
        });
        
        // Batch fix modal
        document.getElementById('start-batch-fix-btn').addEventListener('click', () => {
            this.startBatchFix();
        });
        
        // Batch criteria changes
        ['batch-severity-filter', 'batch-domain-filter', 'batch-max-findings', 'batch-confidence-threshold'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', () => {
                    this.updateBatchPreview();
                });
            }
        });
        
        // Fix details modal buttons
        document.getElementById('retry-fix-btn').addEventListener('click', () => {
            this.retryFix();
        });
        
        document.getElementById('cancel-fix-btn').addEventListener('click', () => {
            this.cancelFix();
        });
    }
    
    /**
     * Load all auto-fix data
     */
    async loadData() {
        try {
            await Promise.all([
                this.loadMetrics(),
                this.loadActiveFixes(),
                this.loadPullRequests(),
                this.loadFixHistory()
            ]);
            
            this.renderCurrentTab();
            
        } catch (error) {
            console.error('Failed to load auto-fix data:', error);
            window.dashboard.showNotification('Failed to load auto-fix data', 'error');
        }
    }
    
    /**
     * Load metrics from API
     */
    async loadMetrics() {
        try {
            // For now, use mock data since API endpoint doesn't exist yet
            this.metrics = {
                fixes_applied: 23,
                fixes_pending: 7,
                active_prs: 5,
                merged_prs: 18,
                success_rate: 85,
                ai_confidence: 78
            };
            
            this.updateMetricsDisplay();
            
        } catch (error) {
            console.error('Failed to load metrics:', error);
        }
    }
    
    /**
     * Load active fixes
     */
    async loadActiveFixes() {
        try {
            // Mock data - replace with actual API call
            this.activeFixes = [
                {
                    id: 'fix_001',
                    finding_id: 'finding_123',
                    title: 'SQL Injection in user login',
                    status: 'generating',
                    progress: 65,
                    severity: 'CRITICAL',
                    domain: 'SAST',
                    started_at: new Date(Date.now() - 300000).toISOString(),
                    estimated_completion: new Date(Date.now() + 120000).toISOString(),
                    ai_confidence: 0.92,
                    current_step: 'Generating parameterized query fix'
                },
                {
                    id: 'fix_002',
                    finding_id: 'finding_124',
                    title: 'XSS in search functionality',
                    status: 'testing',
                    progress: 80,
                    severity: 'HIGH',
                    domain: 'SAST',
                    started_at: new Date(Date.now() - 600000).toISOString(),
                    estimated_completion: new Date(Date.now() + 60000).toISOString(),
                    ai_confidence: 0.87,
                    current_step: 'Running security tests on fix'
                }
            ];
            
        } catch (error) {
            console.error('Failed to load active fixes:', error);
        }
    }
    
    /**
     * Load pull requests
     */
    async loadPullRequests() {
        try {
            // Mock data
            this.pullRequests = [
                {
                    id: 'pr_001',
                    title: 'DevSecure Auto-Fix: SQL Injection and XSS vulnerabilities',
                    number: 42,
                    status: 'open',
                    url: 'https://github.com/user/repo/pull/42',
                    created_at: new Date(Date.now() - 3600000).toISOString(),
                    fixes_count: 3,
                    files_changed: 2,
                    ai_confidence: 0.89,
                    checks_status: 'passed',
                    mergeable: true
                },
                {
                    id: 'pr_002',
                    title: 'DevSecure Auto-Fix: Weak cryptography fixes',
                    number: 41,
                    status: 'merged',
                    url: 'https://github.com/user/repo/pull/41',
                    created_at: new Date(Date.now() - 7200000).toISOString(),
                    merged_at: new Date(Date.now() - 1800000).toISOString(),
                    fixes_count: 2,
                    files_changed: 1,
                    ai_confidence: 0.95,
                    checks_status: 'passed',
                    mergeable: true
                }
            ];
            
        } catch (error) {
            console.error('Failed to load pull requests:', error);
        }
    }
    
    /**
     * Load fix history
     */
    async loadFixHistory() {
        try {
            // Mock data
            this.fixHistory = [
                {
                    id: 'hist_001',
                    finding_title: 'Buffer overflow in input validation',
                    outcome: 'success',
                    started_at: new Date(Date.now() - 86400000).toISOString(),
                    completed_at: new Date(Date.now() - 85800000).toISOString(),
                    duration: 600,
                    ai_confidence: 0.91,
                    pr_url: 'https://github.com/user/repo/pull/40',
                    severity: 'HIGH',
                    domain: 'SAST'
                },
                {
                    id: 'hist_002',
                    finding_title: 'Hardcoded API key in configuration',
                    outcome: 'success',
                    started_at: new Date(Date.now() - 172800000).toISOString(),
                    completed_at: new Date(Date.now() - 172200000).toISOString(),
                    duration: 600,
                    ai_confidence: 0.88,
                    pr_url: 'https://github.com/user/repo/pull/39',
                    severity: 'CRITICAL',
                    domain: 'SECRETS'
                }
            ];
            
        } catch (error) {
            console.error('Failed to load fix history:', error);
        }
    }
    
    /**
     * Update metrics display
     */
    updateMetricsDisplay() {
        const metricElements = {
            'fixes-applied': this.metrics.fixes_applied,
            'fixes-pending': this.metrics.fixes_pending,
            'active-prs': this.metrics.active_prs,
            'merged-prs': this.metrics.merged_prs,
            'success-rate': this.metrics.success_rate + '%',
            'ai-confidence': this.metrics.ai_confidence + '%'
        };
        
        Object.entries(metricElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                if (typeof value === 'number') {
                    window.dashboard.animateCounter(element, parseInt(element.textContent) || 0, value);
                } else {
                    element.textContent = value;
                }
            }
        });
    }
    
    /**
     * Handle tab switching
     */
    onTabSwitch(tabId) {
        switch (tabId) {
            case '#active-fixes':
                this.renderActiveFixes();
                break;
            case '#pr-management':
                this.renderPullRequests();
                break;
            case '#fix-history':
                this.renderFixHistory();
                break;
            case '#effectiveness':
                this.renderEffectivenessCharts();
                break;
        }
    }
    
    /**
     * Render current active tab
     */
    renderCurrentTab() {
        const activeTab = document.querySelector('.nav-link.active');
        if (activeTab) {
            const target = activeTab.getAttribute('data-bs-target');
            this.onTabSwitch(target);
        }
    }
    
    /**
     * Render active fixes list
     */
    renderActiveFixes() {
        const container = document.getElementById('active-fixes-list');
        if (!container) return;
        
        if (this.activeFixes.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-magic fa-3x text-muted mb-3"></i>
                    <h6>No Active Fixes</h6>
                    <p class="text-muted">No auto-fixes are currently in progress</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.activeFixes.map(fix => `
            <div class="card mb-3 border-0 shadow-sm fix-card" data-fix-id="${fix.id}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(fix.title)}</h6>
                            <div class="d-flex gap-2 mb-2">
                                ${window.dashboard.formatSeverity(fix.severity)}
                                ${window.dashboard.formatDomain(fix.domain)}
                                <span class="badge bg-info">AI: ${Math.round(fix.ai_confidence * 100)}%</span>
                            </div>
                            <small class="text-muted">
                                Started: ${window.dashboard.formatTimestamp(fix.started_at)} | 
                                ETA: ${this.formatDuration(new Date(fix.estimated_completion) - new Date())}
                            </small>
                        </div>
                        <div class="text-end">
                            <span class="badge bg-${this.getStatusColor(fix.status)}">${this.formatStatus(fix.status)}</span>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <small class="text-muted">${this.escapeHtml(fix.current_step)}</small>
                            <small class="text-muted">${fix.progress}%</small>
                        </div>
                        <div class="progress" style="height: 6px;">
                            <div class="progress-bar bg-${this.getStatusColor(fix.status)}" 
                                 style="width: ${fix.progress}%"></div>
                        </div>
                    </div>
                    
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewFixDetails('${fix.id}')">
                            <i class="fas fa-eye me-1"></i>Details
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="pauseFix('${fix.id}')">
                            <i class="fas fa-pause me-1"></i>Pause
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="cancelFix('${fix.id}')">
                            <i class="fas fa-stop me-1"></i>Cancel
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render pull requests list
     */
    renderPullRequests() {
        const container = document.getElementById('pr-management-list');
        if (!container) return;
        
        if (this.pullRequests.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-code-branch fa-3x text-muted mb-3"></i>
                    <h6>No Pull Requests</h6>
                    <p class="text-muted">No auto-fix pull requests found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.pullRequests.map(pr => `
            <div class="card mb-3 border-0 shadow-sm pr-card" data-pr-id="${pr.id}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">
                                <a href="${pr.url}" target="_blank" class="text-decoration-none">
                                    ${this.escapeHtml(pr.title)} #${pr.number}
                                    <i class="fas fa-external-link-alt ms-1 small"></i>
                                </a>
                            </h6>
                            <div class="d-flex gap-2 mb-2">
                                <span class="badge bg-${this.getPRStatusColor(pr.status)}">${pr.status.toUpperCase()}</span>
                                <span class="badge bg-light text-dark">${pr.fixes_count} fixes</span>
                                <span class="badge bg-light text-dark">${pr.files_changed} files</span>
                                <span class="badge bg-info">AI: ${Math.round(pr.ai_confidence * 100)}%</span>
                            </div>
                            <small class="text-muted">
                                Created: ${window.dashboard.formatTimestamp(pr.created_at)}
                                ${pr.merged_at ? ` | Merged: ${window.dashboard.formatTimestamp(pr.merged_at)}` : ''}
                            </small>
                        </div>
                        <div class="text-end">
                            <div class="badge bg-${this.getChecksColor(pr.checks_status)}">${pr.checks_status}</div>
                        </div>
                    </div>
                    
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewPRDetails('${pr.id}')">
                            <i class="fas fa-eye me-1"></i>Details
                        </button>
                        ${pr.status === 'open' ? `
                            <button class="btn btn-sm btn-outline-success" onclick="mergePR('${pr.id}')" 
                                    ${!pr.mergeable ? 'disabled' : ''}>
                                <i class="fas fa-merge me-1"></i>Merge
                            </button>
                        ` : ''}
                        <button class="btn btn-sm btn-outline-secondary" onclick="syncSinglePR('${pr.id}')">
                            <i class="fas fa-sync me-1"></i>Sync
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render fix history
     */
    renderFixHistory() {
        const container = document.getElementById('fix-history-list');
        if (!container) return;
        
        if (this.fixHistory.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-history fa-3x text-muted mb-3"></i>
                    <h6>No History</h6>
                    <p class="text-muted">No completed auto-fixes found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.fixHistory.map(history => `
            <div class="card mb-3 border-0 shadow-sm history-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(history.finding_title)}</h6>
                            <div class="d-flex gap-2 mb-2">
                                <span class="badge bg-${this.getOutcomeColor(history.outcome)}">${history.outcome.toUpperCase()}</span>
                                ${window.dashboard.formatSeverity(history.severity)}
                                ${window.dashboard.formatDomain(history.domain)}
                                <span class="badge bg-info">AI: ${Math.round(history.ai_confidence * 100)}%</span>
                            </div>
                            <small class="text-muted">
                                Completed: ${window.dashboard.formatTimestamp(history.completed_at)} | 
                                Duration: ${this.formatDuration(history.duration * 1000)}
                                ${history.pr_url ? ` | <a href="${history.pr_url}" target="_blank">View PR</a>` : ''}
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render effectiveness charts
     */
    renderEffectivenessCharts() {
        setTimeout(() => {
            this.initializeEffectivenessCharts();
        }, 100);
    }
    
    /**
     * Initialize effectiveness charts
     */
    initializeEffectivenessCharts() {
        this.initializeSuccessRateChart();
        this.initializeConfidenceChart();
        this.initializeCategoriesChart();
        this.initializeResolutionTimeChart();
    }
    
    /**
     * Initialize success rate chart
     */
    initializeSuccessRateChart() {
        const ctx = document.getElementById('success-rate-chart');
        if (!ctx || this.charts.successRate) return;
        
        // Generate sample data for the last 30 days
        const labels = [];
        const data = [];
        
        for (let i = 29; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            data.push(Math.random() * 20 + 70); // 70-90% success rate
        }
        
        this.charts.successRate = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Success Rate (%)',
                    data: data,
                    borderColor: '#198754',
                    backgroundColor: 'rgba(25, 135, 84, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    /**
     * Initialize AI confidence chart
     */
    initializeConfidenceChart() {
        const ctx = document.getElementById('confidence-chart');
        if (!ctx || this.charts.confidence) return;
        
        this.charts.confidence = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['90-100%', '80-89%', '70-79%', '60-69%', '<60%'],
                datasets: [{
                    data: [45, 30, 15, 8, 2],
                    backgroundColor: [
                        '#198754',
                        '#20c997',
                        '#ffc107',
                        '#fd7e14',
                        '#dc3545'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
    
    /**
     * Initialize categories chart
     */
    initializeCategoriesChart() {
        const ctx = document.getElementById('categories-chart');
        if (!ctx || this.charts.categories) return;
        
        this.charts.categories = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['SQL Injection', 'XSS', 'Auth Bypass', 'Crypto Weak', 'Input Validation'],
                datasets: [{
                    label: 'Success Rate (%)',
                    data: [92, 85, 78, 95, 88],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#198754',
                        '#0d6efd'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    /**
     * Initialize resolution time chart
     */
    initializeResolutionTimeChart() {
        const ctx = document.getElementById('resolution-time-chart');
        if (!ctx || this.charts.resolutionTime) return;
        
        this.charts.resolutionTime = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['<5 min', '5-10 min', '10-20 min', '20-30 min', '>30 min'],
                datasets: [{
                    label: 'Number of Fixes',
                    data: [12, 18, 8, 3, 1],
                    backgroundColor: '#0d6efd'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    /**
     * Show batch fix modal
     */
    showBatchFixModal() {
        const modal = new bootstrap.Modal(document.getElementById('batchFixModal'));
        this.updateBatchPreview();
        modal.show();
    }
    
    /**
     * Update batch fix preview
     */
    async updateBatchPreview() {
        // Mock preview count
        const count = Math.floor(Math.random() * 20) + 5;
        document.getElementById('batch-preview-count').textContent = count;
    }
    
    /**
     * Start batch fix process
     */
    async startBatchFix() {
        try {
            const severity = document.getElementById('batch-severity-filter').value;
            const domain = document.getElementById('batch-domain-filter').value;
            const maxFindings = document.getElementById('batch-max-findings').value;
            const confidenceThreshold = document.getElementById('batch-confidence-threshold').value;
            const autoMerge = document.getElementById('batch-auto-merge').checked;
            const smartGrouping = document.getElementById('batch-smart-grouping').checked;
            
            // Mock API call
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            window.dashboard.showNotification('Batch fix process started successfully', 'success');
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('batchFixModal'));
            modal.hide();
            
            // Refresh data
            this.loadData();
            
        } catch (error) {
            console.error('Failed to start batch fix:', error);
            window.dashboard.showNotification('Failed to start batch fix', 'error');
        }
    }
    
    /**
     * Start auto-refresh
     */
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            this.loadMetrics();
            this.loadActiveFixes();
            
            // Update active fixes display if visible
            const activeTab = document.querySelector('#active-fixes.show');
            if (activeTab) {
                this.renderActiveFixes();
            }
        }, 10000); // Refresh every 10 seconds
    }
    
    /**
     * Utility functions
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    formatStatus(status) {
        return status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
    
    formatDuration(ms) {
        const minutes = Math.floor(ms / 60000);
        if (minutes < 60) return `${minutes}m`;
        const hours = Math.floor(minutes / 60);
        return `${hours}h ${minutes % 60}m`;
    }
    
    getStatusColor(status) {
        const colors = {
            queued: 'secondary',
            analyzing: 'info',
            generating: 'warning',
            testing: 'primary',
            creating_pr: 'success'
        };
        return colors[status] || 'secondary';
    }
    
    getPRStatusColor(status) {
        const colors = {
            open: 'success',
            merged: 'primary',
            closed: 'secondary',
            draft: 'warning'
        };
        return colors[status] || 'secondary';
    }
    
    getChecksColor(status) {
        const colors = {
            passed: 'success',
            failed: 'danger',
            pending: 'warning'
        };
        return colors[status] || 'secondary';
    }
    
    getOutcomeColor(outcome) {
        const colors = {
            success: 'success',
            failed: 'danger',
            cancelled: 'warning'
        };
        return colors[outcome] || 'secondary';
    }
    
    /**
     * Filter methods
     */
    filterActiveFixes(status) {
        const cards = document.querySelectorAll('.fix-card');
        cards.forEach(card => {
            if (!status || card.querySelector('.badge').textContent.toLowerCase().includes(status)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }
    
    filterPullRequests(status) {
        const cards = document.querySelectorAll('.pr-card');
        cards.forEach(card => {
            if (!status || card.querySelector('.badge').textContent.toLowerCase().includes(status)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }
    
    filterHistory() {
        // Implementation for history filtering
        this.renderFixHistory();
    }
    
    /**
     * Action methods
     */
    async cancelAllFixes() {
        if (!confirm('Are you sure you want to cancel all active fixes?')) return;
        
        try {
            window.dashboard.showNotification('All active fixes cancelled', 'info');
            this.loadActiveFixes();
        } catch (error) {
            window.dashboard.showNotification('Failed to cancel fixes', 'error');
        }
    }
    
    async syncPullRequests() {
        try {
            window.dashboard.showNotification('Syncing with GitHub...', 'info');
            await new Promise(resolve => setTimeout(resolve, 2000));
            window.dashboard.showNotification('Pull requests synced successfully', 'success');
            this.loadPullRequests();
        } catch (error) {
            window.dashboard.showNotification('Failed to sync pull requests', 'error');
        }
    }
    
    /**
     * Cleanup
     */
    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        Object.values(this.charts).forEach(chart => {
            if (chart) chart.destroy();
        });
    }
}

// Global functions for button handlers
window.viewFixDetails = function(fixId) {
    const modal = new bootstrap.Modal(document.getElementById('fixDetailsModal'));
    modal.show();
};

window.pauseFix = function(fixId) {
    window.dashboard.showNotification('Fix paused (feature coming soon)', 'info');
};

window.cancelFix = function(fixId) {
    if (confirm('Are you sure you want to cancel this fix?')) {
        window.dashboard.showNotification('Fix cancelled', 'info');
    }
};

window.viewPRDetails = function(prId) {
    window.dashboard.showNotification('PR details (feature coming soon)', 'info');
};

window.mergePR = function(prId) {
    if (confirm('Are you sure you want to merge this pull request?')) {
        window.dashboard.showNotification('PR merged successfully', 'success');
    }
};

window.syncSinglePR = function(prId) {
    window.dashboard.showNotification('PR synced', 'success');
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.autoFixManager = new AutoFixManager();
});

// Cleanup when leaving page
window.addEventListener('beforeunload', () => {
    if (window.autoFixManager) {
        window.autoFixManager.destroy();
    }
});
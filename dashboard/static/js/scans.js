/**
 * DevSecure Dashboard - Scans Management JavaScript
 * Handle security scan operations and monitoring
 */

class ScansManager {
    constructor() {
        this.activeScans = [];
        this.scanHistory = [];
        this.scheduledScans = [];
        this.scanTemplates = [];
        this.metrics = {
            total_scans: 0,
            running_scans: 0,
            completed_scans: 0,
            failed_scans: 0,
            avg_duration: '0m',
            total_findings: 0
        };
        
        this.currentTab = 'active-scans';
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
                this.currentTab = e.target.getAttribute('data-bs-target').substring(1);
                this.onTabSwitch(this.currentTab);
            });
        });
        
        // New scan modal
        document.getElementById('start-new-scan-btn').addEventListener('click', () => {
            this.startNewScan();
        });
        
        // Template selection
        document.getElementById('scan-template').addEventListener('change', (e) => {
            this.applyTemplate(e.target.value);
        });
        
        // Control buttons
        document.getElementById('refresh-active-scans').addEventListener('click', () => {
            this.refreshActiveScans();
        });
        
        document.getElementById('stop-all-scans').addEventListener('click', () => {
            this.stopAllScans();
        });
        
        // History filters
        document.getElementById('history-date-filter').addEventListener('change', () => {
            this.filterScanHistory();
        });
        
        document.getElementById('history-status-filter').addEventListener('change', () => {
            this.filterScanHistory();
        });
        
        // Export
        document.getElementById('export-history').addEventListener('click', () => {
            this.exportScanHistory();
        });
        
        // Template and schedule buttons
        document.getElementById('create-template-btn').addEventListener('click', () => {
            this.showCreateTemplateModal();
        });
        
        document.getElementById('create-schedule-btn').addEventListener('click', () => {
            this.showCreateScheduleModal();
        });
        
        // Import project
        document.getElementById('import-project-btn').addEventListener('click', () => {
            this.showImportProjectModal();
        });
    }
    
    /**
     * Load all scan data
     */
    async loadData() {
        try {
            await Promise.all([
                this.loadMetrics(),
                this.loadActiveScans(),
                this.loadScanHistory(),
                this.loadScheduledScans(),
                this.loadScanTemplates()
            ]);
            
            this.renderCurrentTab();
            
        } catch (error) {
            console.error('Failed to load scan data:', error);
            window.dashboard.showNotification('Failed to load scan data', 'error');
        }
    }
    
    /**
     * Load scan metrics
     */
    async loadMetrics() {
        try {
            // Mock data - replace with actual API call
            this.metrics = {
                total_scans: 47,
                running_scans: 2,
                completed_scans: 42,
                failed_scans: 3,
                avg_duration: '8.5m',
                total_findings: 234
            };
            
            this.updateMetricsDisplay();
            
        } catch (error) {
            console.error('Failed to load scan metrics:', error);
        }
    }
    
    /**
     * Load active scans
     */
    async loadActiveScans() {
        try {
            // Mock data
            this.activeScans = [
                {
                    id: 'scan_001',
                    name: 'E-commerce Platform Audit',
                    project_path: '/projects/ecommerce-platform',
                    status: 'running',
                    progress: 65,
                    current_domain: 'SCA',
                    domains: ['SAST', 'SCA', 'SECRETS', 'IAC'],
                    started_at: new Date(Date.now() - 600000).toISOString(),
                    estimated_completion: new Date(Date.now() + 300000).toISOString(),
                    priority: 'high',
                    findings_count: 12,
                    auto_fix_enabled: true
                },
                {
                    id: 'scan_002',
                    name: 'API Gateway Security Check',
                    project_path: '/projects/api-gateway',
                    status: 'running',
                    progress: 25,
                    current_domain: 'SAST',
                    domains: ['SAST', 'SECRETS'],
                    started_at: new Date(Date.now() - 300000).toISOString(),
                    estimated_completion: new Date(Date.now() + 600000).toISOString(),
                    priority: 'medium',
                    findings_count: 3,
                    auto_fix_enabled: false
                }
            ];
            
        } catch (error) {
            console.error('Failed to load active scans:', error);
        }
    }
    
    /**
     * Load scan history
     */
    async loadScanHistory() {
        try {
            // Mock data
            this.scanHistory = [
                {
                    id: 'scan_hist_001',
                    name: 'Frontend Application Security Scan',
                    project_path: '/projects/frontend-app',
                    status: 'completed',
                    domains: ['SAST', 'SCA', 'SECRETS'],
                    started_at: new Date(Date.now() - 3600000).toISOString(),
                    completed_at: new Date(Date.now() - 3000000).toISOString(),
                    duration: 600,
                    findings_count: 8,
                    critical_findings: 1,
                    high_findings: 3,
                    auto_fix_applied: 5,
                    priority: 'medium'
                },
                {
                    id: 'scan_hist_002',
                    name: 'Backend Services Comprehensive Audit',
                    project_path: '/projects/backend-services',
                    status: 'completed',
                    domains: ['SAST', 'SCA', 'SECRETS', 'IAC', 'CONTAINERS'],
                    started_at: new Date(Date.now() - 7200000).toISOString(),
                    completed_at: new Date(Date.now() - 6000000).toISOString(),
                    duration: 1200,
                    findings_count: 23,
                    critical_findings: 2,
                    high_findings: 8,
                    auto_fix_applied: 15,
                    priority: 'high'
                }
            ];
            
        } catch (error) {
            console.error('Failed to load scan history:', error);
        }
    }
    
    /**
     * Load scheduled scans
     */
    async loadScheduledScans() {
        try {
            // Mock data
            this.scheduledScans = [
                {
                    id: 'schedule_001',
                    name: 'Daily Security Check',
                    project_path: '/projects/main-app',
                    schedule: '0 2 * * *',
                    schedule_description: 'Daily at 2:00 AM',
                    domains: ['SAST', 'SECRETS'],
                    enabled: true,
                    next_run: new Date(Date.now() + 86400000).toISOString(),
                    last_run: new Date(Date.now() - 86400000).toISOString(),
                    priority: 'medium'
                }
            ];
            
        } catch (error) {
            console.error('Failed to load scheduled scans:', error);
        }
    }
    
    /**
     * Load scan templates
     */
    async loadScanTemplates() {
        try {
            // Mock data
            this.scanTemplates = [
                {
                    id: 'template_quick',
                    name: 'Quick Security Scan',
                    description: 'Fast scan focusing on critical vulnerabilities',
                    domains: ['SAST', 'SECRETS'],
                    auto_fix_enabled: true,
                    estimated_duration: 300
                },
                {
                    id: 'template_comprehensive',
                    name: 'Comprehensive Security Audit',
                    description: 'Full security analysis across all domains',
                    domains: ['SAST', 'SCA', 'SECRETS', 'IAC', 'CONTAINERS'],
                    auto_fix_enabled: true,
                    estimated_duration: 1800
                }
            ];
            
        } catch (error) {
            console.error('Failed to load scan templates:', error);
        }
    }
    
    /**
     * Update metrics display
     */
    updateMetricsDisplay() {
        const metricElements = {
            'total-scans': this.metrics.total_scans,
            'running-scans': this.metrics.running_scans,
            'completed-scans': this.metrics.completed_scans,
            'failed-scans': this.metrics.failed_scans,
            'avg-duration': this.metrics.avg_duration,
            'total-findings': this.metrics.total_findings
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
            case 'active-scans':
                this.renderActiveScans();
                break;
            case 'scan-history':
                this.renderScanHistory();
                break;
            case 'scheduled-scans':
                this.renderScheduledScans();
                break;
            case 'scan-templates':
                this.renderScanTemplates();
                break;
        }
    }
    
    /**
     * Render current active tab
     */
    renderCurrentTab() {
        this.onTabSwitch(this.currentTab);
    }
    
    /**
     * Render active scans
     */
    renderActiveScans() {
        const container = document.getElementById('active-scans-list');
        if (!container) return;
        
        if (this.activeScans.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-search fa-3x text-muted mb-3"></i>
                    <h6>No Active Scans</h6>
                    <p class="text-muted">No security scans are currently running</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.activeScans.map(scan => `
            <div class="card mb-3 border-0 shadow-sm scan-card" data-scan-id="${scan.id}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(scan.name)}</h6>
                            <div class="d-flex gap-2 mb-2">
                                <span class="badge bg-${this.getPriorityColor(scan.priority)}">${scan.priority.toUpperCase()}</span>
                                ${scan.domains.map(domain => window.dashboard.formatDomain(domain)).join('')}
                                ${scan.auto_fix_enabled ? '<span class="badge bg-success">Auto-Fix</span>' : ''}
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-folder me-1"></i>${this.escapeHtml(scan.project_path)} |
                                Started: ${window.dashboard.formatTimestamp(scan.started_at)} |
                                ETA: ${this.formatDuration(new Date(scan.estimated_completion) - new Date())}
                            </small>
                        </div>
                        <div class="text-end">
                            <span class="badge bg-info">RUNNING</span>
                            <div class="small text-muted mt-1">${scan.findings_count} findings</div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <small class="text-muted">
                                <i class="fas fa-cog me-1"></i>Current: ${scan.current_domain}
                            </small>
                            <small class="text-muted">${scan.progress}%</small>
                        </div>
                        <div class="progress" style="height: 6px;">
                            <div class="progress-bar bg-info progress-bar-striped progress-bar-animated" 
                                 style="width: ${scan.progress}%"></div>
                        </div>
                    </div>
                    
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetails('${scan.id}')">
                            <i class="fas fa-eye me-1"></i>Details
                        </button>
                        <button class="btn btn-sm btn-outline-info" onclick="viewScanLogs('${scan.id}')">
                            <i class="fas fa-file-alt me-1"></i>Logs
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="pauseScan('${scan.id}')">
                            <i class="fas fa-pause me-1"></i>Pause
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="stopScan('${scan.id}')">
                            <i class="fas fa-stop me-1"></i>Stop
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render scan history
     */
    renderScanHistory() {
        const container = document.getElementById('scan-history-list');
        if (!container) return;
        
        if (this.scanHistory.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-history fa-3x text-muted mb-3"></i>
                    <h6>No Scan History</h6>
                    <p class="text-muted">No completed scans found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.scanHistory.map(scan => `
            <div class="card mb-3 border-0 shadow-sm history-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(scan.name)}</h6>
                            <div class="d-flex gap-2 mb-2">
                                <span class="badge bg-${this.getStatusColor(scan.status)}">${scan.status.toUpperCase()}</span>
                                <span class="badge bg-${this.getPriorityColor(scan.priority)}">${scan.priority.toUpperCase()}</span>
                                ${scan.domains.map(domain => window.dashboard.formatDomain(domain)).join('')}
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-folder me-1"></i>${this.escapeHtml(scan.project_path)} |
                                Completed: ${window.dashboard.formatTimestamp(scan.completed_at)} |
                                Duration: ${this.formatDuration(scan.duration * 1000)}
                            </small>
                            <div class="mt-2">
                                <small class="text-muted me-3">
                                    <i class="fas fa-bug me-1"></i>Total: ${scan.findings_count}
                                </small>
                                <small class="text-danger me-3">
                                    <i class="fas fa-exclamation-triangle me-1"></i>Critical: ${scan.critical_findings}
                                </small>
                                <small class="text-warning me-3">
                                    <i class="fas fa-exclamation me-1"></i>High: ${scan.high_findings}
                                </small>
                                <small class="text-success">
                                    <i class="fas fa-magic me-1"></i>Auto-Fixed: ${scan.auto_fix_applied}
                                </small>
                            </div>
                        </div>
                        <div class="text-end">
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-primary" onclick="viewScanDetails('${scan.id}')">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-outline-info" onclick="downloadReport('${scan.id}')">
                                    <i class="fas fa-download"></i>
                                </button>
                                <button class="btn btn-outline-secondary" onclick="cloneScan('${scan.id}')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render scheduled scans
     */
    renderScheduledScans() {
        const container = document.getElementById('scheduled-scans-list');
        if (!container) return;
        
        if (this.scheduledScans.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-calendar fa-3x text-muted mb-3"></i>
                    <h6>No Scheduled Scans</h6>
                    <p class="text-muted">No scan schedules configured</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.scheduledScans.map(schedule => `
            <div class="card mb-3 border-0 shadow-sm schedule-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(schedule.name)}</h6>
                            <div class="d-flex gap-2 mb-2">
                                <span class="badge bg-${schedule.enabled ? 'success' : 'secondary'}">
                                    ${schedule.enabled ? 'Enabled' : 'Disabled'}
                                </span>
                                <span class="badge bg-${this.getPriorityColor(schedule.priority)}">${schedule.priority.toUpperCase()}</span>
                                ${schedule.domains.map(domain => window.dashboard.formatDomain(domain)).join('')}
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-folder me-1"></i>${this.escapeHtml(schedule.project_path)} |
                                Schedule: ${schedule.schedule_description}
                            </small>
                            <div class="mt-2">
                                <small class="text-muted me-3">
                                    <i class="fas fa-clock me-1"></i>Next: ${window.dashboard.formatTimestamp(schedule.next_run)}
                                </small>
                                <small class="text-muted">
                                    <i class="fas fa-history me-1"></i>Last: ${window.dashboard.formatTimestamp(schedule.last_run)}
                                </small>
                            </div>
                        </div>
                        <div class="text-end">
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-primary" onclick="editSchedule('${schedule.id}')">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-outline-${schedule.enabled ? 'warning' : 'success'}" 
                                        onclick="toggleSchedule('${schedule.id}')">
                                    <i class="fas fa-${schedule.enabled ? 'pause' : 'play'}"></i>
                                </button>
                                <button class="btn btn-outline-danger" onclick="deleteSchedule('${schedule.id}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Render scan templates
     */
    renderScanTemplates() {
        const container = document.getElementById('scan-templates-list');
        if (!container) return;
        
        if (this.scanTemplates.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-copy fa-3x text-muted mb-3"></i>
                    <h6>No Scan Templates</h6>
                    <p class="text-muted">No scan templates configured</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.scanTemplates.map(template => `
            <div class="card mb-3 border-0 shadow-sm template-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1">${this.escapeHtml(template.name)}</h6>
                            <p class="text-muted mb-2">${this.escapeHtml(template.description)}</p>
                            <div class="d-flex gap-2 mb-2">
                                ${template.domains.map(domain => window.dashboard.formatDomain(domain)).join('')}
                                ${template.auto_fix_enabled ? '<span class="badge bg-success">Auto-Fix</span>' : ''}
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-clock me-1"></i>Est. Duration: ${this.formatDuration(template.estimated_duration * 1000)}
                            </small>
                        </div>
                        <div class="text-end">
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-primary" onclick="useTemplate('${template.id}')">
                                    <i class="fas fa-play me-1"></i>Use
                                </button>
                                <button class="btn btn-outline-secondary" onclick="editTemplate('${template.id}')">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-outline-danger" onclick="deleteTemplate('${template.id}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Start new scan
     */
    async startNewScan() {
        try {
            const scanName = document.getElementById('scan-name').value;
            const projectPath = document.getElementById('new-scan-path').value;
            const priority = document.getElementById('scan-priority').value;
            const autoFixEnabled = document.getElementById('auto-fix-enabled').checked;
            
            // Get selected domains
            const domainCheckboxes = document.querySelectorAll('[id^="new-scan-"]:checked');
            const domains = Array.from(domainCheckboxes).map(cb => cb.value).filter(v => v !== 'on');
            
            if (!scanName || !projectPath || domains.length === 0) {
                window.dashboard.showNotification('Please fill in all required fields', 'error');
                return;
            }
            
            // Start scan via API
            const response = await window.dashboard.apiCall('/api/scan', {
                method: 'POST',
                body: JSON.stringify({
                    name: scanName,
                    project_path: projectPath,
                    domains: domains,
                    priority: priority,
                    auto_fix_enabled: autoFixEnabled
                })
            });
            
            window.dashboard.showNotification('Security scan started successfully', 'success');
            
            // Close modal and refresh active scans
            const modal = bootstrap.Modal.getInstance(document.getElementById('newScanModal'));
            modal.hide();
            
            this.refreshActiveScans();
            
        } catch (error) {
            console.error('Failed to start scan:', error);
            window.dashboard.showNotification('Failed to start scan', 'error');
        }
    }
    
    /**
     * Apply scan template
     */
    applyTemplate(templateId) {
        if (!templateId) return;
        
        const template = this.scanTemplates.find(t => t.id === `template_${templateId}`);
        if (!template) return;
        
        // Update domain selections
        const allDomainCheckboxes = document.querySelectorAll('[id^="new-scan-"]');
        allDomainCheckboxes.forEach(checkbox => {
            checkbox.checked = template.domains.includes(checkbox.value);
        });
        
        // Update auto-fix setting
        document.getElementById('auto-fix-enabled').checked = template.auto_fix_enabled;
    }
    
    /**
     * Start auto-refresh for active scans
     */
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            if (this.currentTab === 'active-scans') {
                this.loadActiveScans().then(() => {
                    this.renderActiveScans();
                });
            }
            this.loadMetrics();
        }, 5000);
    }
    
    /**
     * Refresh active scans
     */
    async refreshActiveScans() {
        await this.loadActiveScans();
        if (this.currentTab === 'active-scans') {
            this.renderActiveScans();
        }
    }
    
    /**
     * Stop all scans
     */
    async stopAllScans() {
        if (!confirm('Are you sure you want to stop all running scans?')) return;
        
        try {
            window.dashboard.showNotification('Stopping all active scans...', 'info');
            
            // Mock API call
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            window.dashboard.showNotification('All scans stopped', 'success');
            this.refreshActiveScans();
            
        } catch (error) {
            window.dashboard.showNotification('Failed to stop scans', 'error');
        }
    }
    
    /**
     * Filter scan history
     */
    filterScanHistory() {
        // Implementation for filtering scan history
        this.renderScanHistory();
    }
    
    /**
     * Export scan history
     */
    exportScanHistory() {
        const data = this.scanHistory;
        const blob = new Blob([JSON.stringify(data, null, 2)], { 
            type: 'application/json' 
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `devsecure-scan-history-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
    }
    
    /**
     * Show modal functions (placeholder implementations)
     */
    showCreateTemplateModal() {
        window.dashboard.showNotification('Create template feature coming soon', 'info');
    }
    
    showCreateScheduleModal() {
        window.dashboard.showNotification('Create schedule feature coming soon', 'info');
    }
    
    showImportProjectModal() {
        window.dashboard.showNotification('Import project feature coming soon', 'info');
    }
    
    /**
     * Utility functions
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    formatDuration(ms) {
        const minutes = Math.floor(ms / 60000);
        if (minutes < 60) return `${minutes}m`;
        const hours = Math.floor(minutes / 60);
        return `${hours}h ${minutes % 60}m`;
    }
    
    getPriorityColor(priority) {
        const colors = {
            urgent: 'danger',
            high: 'warning',
            medium: 'info',
            low: 'secondary'
        };
        return colors[priority] || 'secondary';
    }
    
    getStatusColor(status) {
        const colors = {
            completed: 'success',
            failed: 'danger',
            cancelled: 'warning',
            running: 'info'
        };
        return colors[status] || 'secondary';
    }
    
    /**
     * Cleanup
     */
    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }
}

// Global functions for scan actions
window.viewScanDetails = function(scanId) {
    const modal = new bootstrap.Modal(document.getElementById('scanDetailsModal'));
    modal.show();
};

window.viewScanLogs = function(scanId) {
    window.dashboard.showNotification('Scan logs feature coming soon', 'info');
};

window.pauseScan = function(scanId) {
    window.dashboard.showNotification('Scan paused (feature coming soon)', 'info');
};

window.stopScan = function(scanId) {
    if (confirm('Are you sure you want to stop this scan?')) {
        window.dashboard.showNotification('Scan stopped', 'info');
    }
};

window.downloadReport = function(scanId) {
    window.dashboard.showNotification('Report download feature coming soon', 'info');
};

window.cloneScan = function(scanId) {
    window.dashboard.showNotification('Clone scan feature coming soon', 'info');
};

window.editSchedule = function(scheduleId) {
    window.dashboard.showNotification('Edit schedule feature coming soon', 'info');
};

window.toggleSchedule = function(scheduleId) {
    window.dashboard.showNotification('Schedule toggled', 'success');
};

window.deleteSchedule = function(scheduleId) {
    if (confirm('Are you sure you want to delete this schedule?')) {
        window.dashboard.showNotification('Schedule deleted', 'success');
    }
};

window.useTemplate = function(templateId) {
    // Open new scan modal with template applied
    const modal = new bootstrap.Modal(document.getElementById('newScanModal'));
    modal.show();
    
    setTimeout(() => {
        if (window.scansManager) {
            window.scansManager.applyTemplate(templateId.replace('template_', ''));
        }
    }, 500);
};

window.editTemplate = function(templateId) {
    window.dashboard.showNotification('Edit template feature coming soon', 'info');
};

window.deleteTemplate = function(templateId) {
    if (confirm('Are you sure you want to delete this template?')) {
        window.dashboard.showNotification('Template deleted', 'success');
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.scansManager = new ScansManager();
});

// Cleanup when leaving page
window.addEventListener('beforeunload', () => {
    if (window.scansManager) {
        window.scansManager.destroy();
    }
});
/**
 * DevSecure Dashboard - Common JavaScript Functions
 * Shared utilities and Socket.IO connection management
 */

class DevSecureDashboard {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.currentScanId = null;
        this.metrics = {
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            auto_fixed: 0,
            pending_fixes: 0,
            scan_status: 'idle'
        };
        
        this.initializeSocketIO();
        this.loadInitialData();
        this.setupEventListeners();
    }
    
    /**
     * Initialize Socket.IO connection
     */
    initializeSocketIO() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.isConnected = true;
            this.updateConnectionStatus(true);
            this.showNotification('Connected to DevSecure Dashboard', 'success');
        });
        
        this.socket.on('disconnect', () => {
            this.isConnected = false;
            this.updateConnectionStatus(false);
            this.showNotification('Disconnected from server', 'warning');
        });
        
        this.socket.on('metrics_update', (data) => {
            this.updateMetrics(data);
        });
        
        this.socket.on('scan_update', (data) => {
            this.handleScanUpdate(data);
        });
        
        this.socket.on('scan_progress', (data) => {
            this.handleScanProgress(data);
        });
        
        this.socket.on('scan_complete', (data) => {
            this.handleScanComplete(data);
        });
        
        this.socket.on('scan_error', (data) => {
            this.handleScanError(data);
        });
    }
    
    /**
     * Load initial data from API
     */
    async loadInitialData() {
        try {
            const response = await fetch('/api/metrics');
            if (response.ok) {
                const metrics = await response.json();
                this.updateMetrics(metrics);
            }
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.showNotification('Failed to load dashboard data', 'error');
        }
    }
    
    /**
     * Setup common event listeners
     */
    setupEventListeners() {
        // Quick scan form handler
        const quickScanForm = document.getElementById('quick-scan-form');
        const startScanBtn = document.getElementById('start-scan-btn');
        
        if (startScanBtn) {
            startScanBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.startQuickScan();
            });
        }
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (this.isConnected) {
                this.refreshData();
            }
        }, 30000);
    }
    
    /**
     * Update connection status indicator
     */
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        if (statusElement) {
            if (connected) {
                statusElement.className = 'badge bg-success connected';
                statusElement.innerHTML = '<i class="fas fa-wifi me-1"></i>Connected';
            } else {
                statusElement.className = 'badge bg-danger disconnected';
                statusElement.innerHTML = '<i class="fas fa-wifi me-1"></i>Disconnected';
            }
        }
    }
    
    /**
     * Update metrics display
     */
    updateMetrics(metrics) {
        this.metrics = { ...this.metrics, ...metrics };
        
        // Update metric cards
        const metricElements = {
            'total-findings': metrics.total_findings,
            'critical-findings': metrics.critical_findings,
            'high-findings': metrics.high_findings,
            'medium-findings': metrics.medium_findings,
            'auto-fixed': metrics.auto_fixed,
            'pending-fixes': metrics.pending_fixes
        };
        
        Object.entries(metricElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateCounter(element, parseInt(element.textContent) || 0, value);
            }
        });
        
        // Update charts if they exist
        if (typeof this.updateCharts === 'function') {
            this.updateCharts(metrics);
        }
    }
    
    /**
     * Animate counter from current to new value
     */
    animateCounter(element, start, end, duration = 1000) {
        const range = end - start;
        const startTime = performance.now();
        
        const updateCounter = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const current = Math.round(start + range * progress);
            
            element.textContent = current.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(updateCounter);
            }
        };
        
        requestAnimationFrame(updateCounter);
    }
    
    /**
     * Start a quick scan
     */
    async startQuickScan() {
        const projectPath = document.getElementById('project-path').value.trim();
        if (!projectPath) {
            this.showNotification('Please enter a project path', 'error');
            return;
        }
        
        // Get selected domains
        const domainCheckboxes = document.querySelectorAll('[id^="domain-"]:checked');
        const domains = Array.from(domainCheckboxes).map(cb => cb.value);
        
        if (domains.length === 0) {
            this.showNotification('Please select at least one security domain', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    project_path: projectPath,
                    domains: domains
                })
            });
            
            if (response.ok) {
                const result = await response.json();
                this.currentScanId = result.scan_id;
                
                // Join scan room for real-time updates
                this.socket.emit('join_scan', { scan_id: result.scan_id });
                
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('quickScanModal'));
                if (modal) {
                    modal.hide();
                }
                
                this.showNotification('Scan started successfully', 'success');
                
                // Update UI to show active scan
                this.addActiveScan(result);
                
            } else {
                const error = await response.json();
                this.showNotification(error.error || 'Failed to start scan', 'error');
            }
        } catch (error) {
            console.error('Scan start error:', error);
            this.showNotification('Failed to start scan', 'error');
        }
    }
    
    /**
     * Handle scan update events
     */
    handleScanUpdate(data) {
        this.updateScanStatus(data.scan_id, data.status, data.message);
    }
    
    /**
     * Handle scan progress events
     */
    handleScanProgress(data) {
        this.updateScanProgress(data.scan_id, data.progress, data.current_domain);
    }
    
    /**
     * Handle scan completion
     */
    handleScanComplete(data) {
        this.updateScanStatus(data.scan_id, 'completed', data.message);
        this.showNotification(`Scan completed: ${data.findings_count} findings found`, 'success');
        
        // Refresh data to get latest metrics
        this.refreshData();
    }
    
    /**
     * Handle scan errors
     */
    handleScanError(data) {
        this.updateScanStatus(data.scan_id, 'failed', data.message);
        this.showNotification(`Scan failed: ${data.error}`, 'error');
    }
    
    /**
     * Add active scan to UI
     */
    addActiveScan(scanData) {
        const container = document.getElementById('active-scans-list');
        if (!container) return;
        
        // Remove "no scans" message
        const noScansMsg = container.querySelector('.text-center');
        if (noScansMsg) {
            noScansMsg.remove();
        }
        
        const scanElement = document.createElement('div');
        scanElement.className = 'scan-progress-item fade-in';
        scanElement.id = `scan-${scanData.scan_id}`;
        scanElement.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <div>
                    <h6 class="mb-0">${scanData.project_path}</h6>
                    <small class="text-muted">Scan ID: ${scanData.scan_id}</small>
                </div>
                <span class="scan-status running">Running</span>
            </div>
            <div class="progress mb-2">
                <div class="progress-bar bg-primary" role="progressbar" style="width: 0%"></div>
            </div>
            <div class="d-flex justify-content-between align-items-center">
                <small class="current-domain text-muted">Initializing...</small>
                <small class="findings-count text-muted">0 findings</small>
            </div>
        `;
        
        container.appendChild(scanElement);
        
        // Update active scans count
        this.updateActiveScanCount();
    }
    
    /**
     * Update scan status in UI
     */
    updateScanStatus(scanId, status, message) {
        const scanElement = document.getElementById(`scan-${scanId}`);
        if (!scanElement) return;
        
        const statusElement = scanElement.querySelector('.scan-status');
        if (statusElement) {
            statusElement.className = `scan-status ${status}`;
            statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }
        
        if (status === 'completed' || status === 'failed') {
            // Move to completed scans after delay
            setTimeout(() => {
                scanElement.remove();
                this.updateActiveScanCount();
            }, 5000);
        }
    }
    
    /**
     * Update scan progress in UI
     */
    updateScanProgress(scanId, progress, currentDomain) {
        const scanElement = document.getElementById(`scan-${scanId}`);
        if (!scanElement) return;
        
        const progressBar = scanElement.querySelector('.progress-bar');
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }
        
        const domainElement = scanElement.querySelector('.current-domain');
        if (domainElement && currentDomain) {
            domainElement.textContent = `Scanning: ${currentDomain}`;
        }
    }
    
    /**
     * Update active scan count
     */
    updateActiveScanCount() {
        const count = document.querySelectorAll('.scan-progress-item').length;
        const countElement = document.getElementById('active-scans-count');
        if (countElement) {
            countElement.textContent = count;
        }
    }
    
    /**
     * Refresh dashboard data
     */
    async refreshData() {
        try {
            const response = await fetch('/api/metrics');
            if (response.ok) {
                const metrics = await response.json();
                this.updateMetrics(metrics);
            }
        } catch (error) {
            console.error('Failed to refresh data:', error);
        }
    }
    
    /**
     * Show notification
     */
    showNotification(message, type = 'info', duration = 5000) {
        const alertsContainer = document.getElementById('alerts-container');
        if (!alertsContainer) return;
        
        const alertTypes = {
            success: 'alert-success',
            error: 'alert-danger',
            warning: 'alert-warning',
            info: 'alert-info'
        };
        
        const alert = document.createElement('div');
        alert.className = `alert ${alertTypes[type]} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        alertsContainer.appendChild(alert);
        
        // Auto-dismiss after duration
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, duration);
    }
    
    /**
     * Format severity for display
     */
    formatSeverity(severity) {
        const severityClasses = {
            CRITICAL: 'severity-critical',
            HIGH: 'severity-high',
            MEDIUM: 'severity-medium',
            LOW: 'severity-low'
        };
        
        return `<span class="severity-badge ${severityClasses[severity] || 'severity-low'}">${severity}</span>`;
    }
    
    /**
     * Format domain for display
     */
    formatDomain(domain) {
        const domainClasses = {
            SAST: 'domain-sast',
            SCA: 'domain-sca',
            SECRETS: 'domain-secrets',
            IAC: 'domain-iac',
            CONTAINERS: 'domain-containers'
        };
        
        return `<span class="domain-badge ${domainClasses[domain] || 'domain-sast'}">${domain}</span>`;
    }
    
    /**
     * Format timestamp for display
     */
    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) { // Less than 1 minute
            return 'Just now';
        } else if (diff < 3600000) { // Less than 1 hour
            return `${Math.floor(diff / 60000)} minutes ago`;
        } else if (diff < 86400000) { // Less than 1 day
            return `${Math.floor(diff / 3600000)} hours ago`;
        } else {
            return date.toLocaleDateString();
        }
    }
    
    /**
     * Utility function to fetch JSON from API
     */
    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(endpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            throw error;
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DevSecureDashboard();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DevSecureDashboard;
}
/**
 * DevSecure Dashboard - Main Dashboard Page JavaScript
 * Charts, visualizations and dashboard-specific functionality
 */

class DashboardCharts {
    constructor() {
        this.charts = {};
        this.chartColors = {
            primary: '#0d6efd',
            secondary: '#6c757d',
            success: '#198754',
            danger: '#dc3545',
            warning: '#ffc107',
            info: '#0dcaf0',
            light: '#f8f9fa',
            dark: '#212529'
        };
        
        this.initializeCharts();
        this.loadChartData();
    }
    
    /**
     * Initialize all dashboard charts
     */
    initializeCharts() {
        this.initializeDomainsChart();
        this.initializeSeverityChart();
        this.initializeTimelineChart();
    }
    
    /**
     * Initialize Security Domains pie chart
     */
    initializeDomainsChart() {
        const ctx = document.getElementById('domains-chart');
        if (!ctx) return;
        
        this.charts.domains = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['SAST', 'SCA', 'Secrets', 'IaC', 'Containers'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        this.chartColors.primary,
                        this.chartColors.success,
                        this.chartColors.danger,
                        this.chartColors.warning,
                        '#6f42c1'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} findings (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '60%',
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        });
    }
    
    /**
     * Initialize Severity Distribution bar chart
     */
    initializeSeverityChart() {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;
        
        this.charts.severity = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Findings',
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        this.chartColors.danger,
                        '#fd7e14',
                        this.chartColors.warning,
                        this.chartColors.info
                    ],
                    borderColor: [
                        this.chartColors.danger,
                        '#fd7e14',
                        this.chartColors.warning,
                        this.chartColors.info
                    ],
                    borderWidth: 1,
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            title: function(context) {
                                return `${context[0].label} Severity`;
                            },
                            label: function(context) {
                                return `Findings: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            callback: function(value) {
                                return Number.isInteger(value) ? value : '';
                            }
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                animation: {
                    delay: (context) => {
                        return context.dataIndex * 100;
                    }
                }
            }
        });
    }
    
    /**
     * Initialize Scan Timeline line chart
     */
    initializeTimelineChart() {
        const ctx = document.getElementById('timeline-chart');
        if (!ctx) return;
        
        // Generate sample timeline data for the last 7 days
        const now = new Date();
        const labels = [];
        const scanData = [];
        const findingsData = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            scanData.push(Math.floor(Math.random() * 10) + 1);
            findingsData.push(Math.floor(Math.random() * 50) + 10);
        }
        
        this.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Scans',
                        data: scanData,
                        borderColor: this.chartColors.primary,
                        backgroundColor: `${this.chartColors.primary}20`,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Findings',
                        data: findingsData,
                        borderColor: this.chartColors.danger,
                        backgroundColor: `${this.chartColors.danger}20`,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 15
                        }
                    },
                    tooltip: {
                        callbacks: {
                            title: function(context) {
                                return `${context[0].label}`;
                            },
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Scans'
                        }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Findings'
                        },
                        grid: {
                            drawOnChartArea: false,
                        }
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeOutCubic'
                }
            }
        });
    }
    
    /**
     * Update charts with new data
     */
    updateCharts(metrics) {
        this.updateDomainsChart(metrics);
        this.updateSeverityChart(metrics);
    }
    
    /**
     * Update domains chart with new data
     */
    updateDomainsChart(metrics) {
        if (!this.charts.domains) return;
        
        // Sample domain distribution (would come from API)
        const domainData = [
            metrics.total_findings * 0.3, // SAST
            metrics.total_findings * 0.25, // SCA
            metrics.total_findings * 0.2,  // Secrets
            metrics.total_findings * 0.15, // IaC
            metrics.total_findings * 0.1   // Containers
        ].map(v => Math.floor(v));
        
        this.charts.domains.data.datasets[0].data = domainData;
        this.charts.domains.update('active');
    }
    
    /**
     * Update severity chart with new data
     */
    updateSeverityChart(metrics) {
        if (!this.charts.severity) return;
        
        const severityData = [
            metrics.critical_findings || 0,
            metrics.high_findings || 0,
            metrics.medium_findings || 0,
            metrics.low_findings || 0
        ];
        
        this.charts.severity.data.datasets[0].data = severityData;
        this.charts.severity.update('active');
    }
    
    /**
     * Load chart data from API
     */
    async loadChartData() {
        try {
            // Load metrics
            const metricsResponse = await fetch('/api/metrics');
            if (metricsResponse.ok) {
                const metrics = await metricsResponse.json();
                this.updateCharts(metrics);
            }
            
            // Load scan timeline data (would be a separate endpoint)
            // For now, keeping the sample data
            
        } catch (error) {
            console.error('Failed to load chart data:', error);
        }
    }
    
    /**
     * Destroy all charts (for cleanup)
     */
    destroy() {
        Object.values(this.charts).forEach(chart => {
            if (chart) {
                chart.destroy();
            }
        });
        this.charts = {};
    }
}

class DashboardRecentActivity {
    constructor() {
        this.loadRecentFindings();
        this.setupAutoRefresh();
    }
    
    /**
     * Load recent findings
     */
    async loadRecentFindings() {
        try {
            const response = await fetch('/api/findings?limit=5&offset=0');
            if (response.ok) {
                const data = await response.json();
                this.displayRecentFindings(data.findings);
            }
        } catch (error) {
            console.error('Failed to load recent findings:', error);
        }
    }
    
    /**
     * Display recent findings in the UI
     */
    displayRecentFindings(findings) {
        const container = document.getElementById('recent-findings-list');
        if (!container) return;
        
        if (findings.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="fas fa-bug fa-3x mb-3 opacity-50"></i>
                    <p class="mb-0">No recent findings</p>
                    <small>Run a security scan to see findings here</small>
                </div>
            `;
            return;
        }
        
        container.innerHTML = findings.map(finding => `
            <div class="finding-item slide-in-right">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div class="flex-grow-1">
                        <h6 class="mb-1 text-truncate">${this.escapeHtml(finding.title)}</h6>
                        <small class="text-muted">${this.escapeHtml(finding.file_path)}</small>
                    </div>
                    <div class="text-end">
                        ${window.dashboard.formatSeverity(finding.severity)}
                        ${window.dashboard.formatDomain(finding.domain)}
                    </div>
                </div>
                <p class="mb-1 text-muted small text-truncate-2">${this.escapeHtml(finding.description)}</p>
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted">
                        <i class="fas fa-clock me-1"></i>
                        ${window.dashboard.formatTimestamp(finding.timestamp || new Date())}
                    </small>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewFindingDetail('${finding.id}')">
                        View <i class="fas fa-arrow-right ms-1"></i>
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Setup auto-refresh for recent activity
     */
    setupAutoRefresh() {
        setInterval(() => {
            this.loadRecentFindings();
        }, 60000); // Refresh every minute
    }
    
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global function to view finding details
function viewFindingDetail(findingId) {
    // Navigate to findings page with specific finding selected
    window.location.href = `/findings?id=${findingId}`;
}

// Initialize dashboard components when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize charts
    window.dashboardCharts = new DashboardCharts();
    
    // Initialize recent activity
    window.recentActivity = new DashboardRecentActivity();
    
    // Extend the main dashboard object to include chart updates
    if (window.dashboard) {
        const originalUpdateCharts = window.dashboard.updateCharts;
        window.dashboard.updateCharts = function(metrics) {
            if (window.dashboardCharts) {
                window.dashboardCharts.updateCharts(metrics);
            }
            if (originalUpdateCharts) {
                originalUpdateCharts.call(this, metrics);
            }
        };
    }
});

// Cleanup when leaving page
window.addEventListener('beforeunload', () => {
    if (window.dashboardCharts) {
        window.dashboardCharts.destroy();
    }
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DashboardCharts, DashboardRecentActivity };
}
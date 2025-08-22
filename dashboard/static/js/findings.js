/**
 * DevSecure Dashboard - Findings Page JavaScript
 * Interactive findings table, filtering, and bulk operations
 */

class FindingsManager {
    constructor() {
        this.findings = [];
        this.filteredFindings = [];
        this.selectedFindings = new Set();
        this.currentPage = 1;
        this.itemsPerPage = 25;
        this.sortField = 'severity';
        this.sortDirection = 'desc';
        this.filters = {
            search: '',
            domain: '',
            severity: '',
            status: ''
        };
        
        this.initializeEventListeners();
        this.loadFindings();
    }
    
    /**
     * Initialize event listeners
     */
    initializeEventListeners() {
        // Search input
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', this.debounce((e) => {
                this.filters.search = e.target.value;
                this.applyFilters();
            }, 300));
        }
        
        // Filter dropdowns
        ['domain-filter', 'severity-filter', 'status-filter'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', (e) => {
                    const filterType = id.replace('-filter', '');
                    this.filters[filterType] = e.target.value;
                    this.applyFilters();
                });
            }
        });
        
        // Clear filters button
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', () => {
                this.clearFilters();
            });
        }
        
        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadFindings();
            });
        }
        
        // Select all checkbox
        const selectAllCheckbox = document.getElementById('select-all-checkbox');
        const headerSelectAll = document.getElementById('header-select-all');
        
        [selectAllCheckbox, headerSelectAll].forEach(checkbox => {
            if (checkbox) {
                checkbox.addEventListener('change', (e) => {
                    this.toggleSelectAll(e.target.checked);
                });
            }
        });
        
        // Bulk auto-fix button
        const bulkAutofixBtn = document.getElementById('bulk-autofix-btn');
        if (bulkAutofixBtn) {
            bulkAutofixBtn.addEventListener('click', () => {
                this.showBulkAutofixModal();
            });
        }
        
        // Confirm bulk auto-fix
        const confirmBulkAutofixBtn = document.getElementById('confirm-bulk-autofix-btn');
        if (confirmBulkAutofixBtn) {
            confirmBulkAutofixBtn.addEventListener('click', () => {
                this.startBulkAutofix();
            });
        }
        
        // Export button
        const exportBtn = document.getElementById('export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportFindings();
            });
        }
        
        // Table sorting
        const sortHeaders = document.querySelectorAll('[data-sort]');
        sortHeaders.forEach(header => {
            header.addEventListener('click', () => {
                const field = header.getAttribute('data-sort');
                this.toggleSort(field);
            });
        });
    }
    
    /**
     * Load findings from API
     */
    async loadFindings() {
        try {
            this.showLoading(true);
            
            const response = await window.dashboard.apiCall('/api/findings?limit=1000');
            this.findings = response.findings || [];
            
            this.applyFilters();
            
        } catch (error) {
            console.error('Failed to load findings:', error);
            window.dashboard.showNotification('Failed to load findings', 'error');
            this.showEmptyState();
        } finally {
            this.showLoading(false);
        }
    }
    
    /**
     * Apply current filters to findings
     */
    applyFilters() {
        let filtered = [...this.findings];
        
        // Apply search filter
        if (this.filters.search) {
            const search = this.filters.search.toLowerCase();
            filtered = filtered.filter(finding => 
                finding.title.toLowerCase().includes(search) ||
                finding.description.toLowerCase().includes(search) ||
                finding.file_path.toLowerCase().includes(search)
            );
        }
        
        // Apply domain filter
        if (this.filters.domain) {
            filtered = filtered.filter(finding => finding.domain === this.filters.domain);
        }
        
        // Apply severity filter
        if (this.filters.severity) {
            filtered = filtered.filter(finding => finding.severity === this.filters.severity);
        }
        
        // Apply status filter
        if (this.filters.status) {
            filtered = filtered.filter(finding => finding.status === this.filters.status);
        }
        
        // Apply sorting
        this.sortFindings(filtered);
        
        this.filteredFindings = filtered;
        this.currentPage = 1;
        
        this.updateSummaryStats();
        this.renderTable();
        this.renderPagination();
    }
    
    /**
     * Sort findings by field and direction
     */
    sortFindings(findings) {
        const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        
        findings.sort((a, b) => {
            let aVal = a[this.sortField];
            let bVal = b[this.sortField];
            
            // Special handling for severity
            if (this.sortField === 'severity') {
                aVal = severityOrder[aVal] || 0;
                bVal = severityOrder[bVal] || 0;
            }
            
            // String comparison
            if (typeof aVal === 'string' && typeof bVal === 'string') {
                aVal = aVal.toLowerCase();
                bVal = bVal.toLowerCase();
            }
            
            let result = 0;
            if (aVal < bVal) result = -1;
            else if (aVal > bVal) result = 1;
            
            return this.sortDirection === 'desc' ? -result : result;
        });
    }
    
    /**
     * Toggle sort field and direction
     */
    toggleSort(field) {
        if (this.sortField === field) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortField = field;
            this.sortDirection = 'desc';
        }
        
        // Update sort icons
        this.updateSortIcons();
        
        this.applyFilters();
    }
    
    /**
     * Update sort icons in table headers
     */
    updateSortIcons() {
        const headers = document.querySelectorAll('[data-sort]');
        headers.forEach(header => {
            const icon = header.querySelector('i');
            const field = header.getAttribute('data-sort');
            
            if (field === this.sortField) {
                icon.className = `fas fa-sort-${this.sortDirection === 'asc' ? 'up' : 'down'}`;
            } else {
                icon.className = 'fas fa-sort text-muted';
            }
        });
    }
    
    /**
     * Clear all filters
     */
    clearFilters() {
        this.filters = {
            search: '',
            domain: '',
            severity: '',
            status: ''
        };
        
        // Reset form elements
        document.getElementById('search-input').value = '';
        document.getElementById('domain-filter').value = '';
        document.getElementById('severity-filter').value = '';
        document.getElementById('status-filter').value = '';
        
        this.applyFilters();
    }
    
    /**
     * Update summary statistics
     */
    updateSummaryStats() {
        const stats = {
            total: this.filteredFindings.length,
            critical: this.filteredFindings.filter(f => f.severity === 'CRITICAL').length,
            high: this.filteredFindings.filter(f => f.severity === 'HIGH').length,
            selected: this.selectedFindings.size,
            autoFixable: this.filteredFindings.filter(f => f.auto_fixable !== false).length,
            pending: this.filteredFindings.filter(f => f.status === 'in_progress').length
        };
        
        Object.entries(stats).forEach(([key, value]) => {
            const element = document.getElementById(`filtered-${key}` || `filtered-${key.replace(/([A-Z])/g, '-$1'.toLowerCase())}`);
            if (element) {
                window.dashboard.animateCounter(element, parseInt(element.textContent) || 0, value);
            }
        });
    }
    
    /**
     * Render findings table
     */
    renderTable() {
        const tbody = document.getElementById('findings-table-body');
        if (!tbody) return;
        
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const pageFindings = this.filteredFindings.slice(startIndex, endIndex);
        
        if (pageFindings.length === 0) {
            this.showEmptyState();
            return;
        }
        
        this.showTable();
        
        tbody.innerHTML = pageFindings.map(finding => this.renderFindingRow(finding)).join('');
        
        // Update pagination info
        document.getElementById('showing-start').textContent = startIndex + 1;
        document.getElementById('showing-end').textContent = Math.min(endIndex, this.filteredFindings.length);
        document.getElementById('showing-total').textContent = this.filteredFindings.length;
        
        // Add event listeners to checkboxes
        tbody.querySelectorAll('.finding-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                this.toggleFindingSelection(e.target.value, e.target.checked);
            });
        });
        
        // Update checkbox states
        this.updateCheckboxStates();
    }
    
    /**
     * Render a single finding row
     */
    renderFindingRow(finding) {
        const isSelected = this.selectedFindings.has(finding.id);
        
        return `
            <tr class="finding-row ${isSelected ? 'table-active' : ''}" data-finding-id="${finding.id}">
                <td>
                    <div class="form-check">
                        <input class="form-check-input finding-checkbox" type="checkbox" 
                               value="${finding.id}" ${isSelected ? 'checked' : ''}>
                    </div>
                </td>
                <td>
                    ${window.dashboard.formatSeverity(finding.severity)}
                </td>
                <td>
                    ${window.dashboard.formatDomain(finding.domain)}
                </td>
                <td>
                    <div class="d-flex flex-column">
                        <span class="fw-medium text-truncate" style="max-width: 300px;" 
                              title="${this.escapeHtml(finding.title)}">
                            ${this.escapeHtml(finding.title)}
                        </span>
                        <small class="text-muted text-truncate" style="max-width: 300px;" 
                               title="${this.escapeHtml(finding.description)}">
                            ${this.escapeHtml(finding.description)}
                        </small>
                    </div>
                </td>
                <td>
                    <div class="d-flex flex-column">
                        <span class="text-truncate" style="max-width: 200px;" 
                              title="${this.escapeHtml(finding.file_path)}">
                            <i class="fas fa-file-code me-1 text-muted"></i>
                            ${this.getFileName(finding.file_path)}
                        </span>
                        <small class="text-muted">${this.escapeHtml(finding.file_path)}</small>
                    </div>
                </td>
                <td>
                    ${finding.line_start > 0 ? 
                        `<span class="badge bg-light text-dark">${finding.line_start}${finding.line_end !== finding.line_start ? `-${finding.line_end}` : ''}</span>` : 
                        '<span class="text-muted">-</span>'
                    }
                </td>
                <td>
                    ${finding.cwe ? 
                        `<a href="https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html" 
                            target="_blank" class="text-decoration-none">
                            <span class="badge bg-info">${finding.cwe}</span>
                        </a>` : 
                        '<span class="text-muted">-</span>'
                    }
                </td>
                <td>
                    ${finding.cvss_score ? 
                        `<span class="badge ${this.getCvssClass(finding.cvss_score)}">${finding.cvss_score}</span>` : 
                        '<span class="text-muted">-</span>'
                    }
                </td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="viewFindingDetail('${finding.id}')" 
                                title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="startSingleAutofix('${finding.id}')" 
                                title="Auto-Fix" ${finding.auto_fixable === false ? 'disabled' : ''}>
                            <i class="fas fa-magic"></i>
                        </button>
                        <div class="btn-group" role="group">
                            <button class="btn btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" 
                                    title="More Actions">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="#" onclick="markFalsePositive('${finding.id}')">
                                    <i class="fas fa-times-circle me-2"></i>False Positive
                                </a></li>
                                <li><a class="dropdown-item" href="#" onclick="assignFinding('${finding.id}')">
                                    <i class="fas fa-user me-2"></i>Assign
                                </a></li>
                                <li><a class="dropdown-item" href="#" onclick="addComment('${finding.id}')">
                                    <i class="fas fa-comment me-2"></i>Add Comment
                                </a></li>
                            </ul>
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }
    
    /**
     * Render pagination
     */
    renderPagination() {
        const totalPages = Math.ceil(this.filteredFindings.length / this.itemsPerPage);
        const pagination = document.getElementById('findings-pagination');
        
        if (!pagination || totalPages <= 1) {
            if (pagination) pagination.innerHTML = '';
            return;
        }
        
        let html = '';
        
        // Previous button
        html += `
            <li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${this.currentPage - 1}">
                    <i class="fas fa-chevron-left"></i>
                </a>
            </li>
        `;
        
        // Page numbers
        const startPage = Math.max(1, this.currentPage - 2);
        const endPage = Math.min(totalPages, this.currentPage + 2);
        
        if (startPage > 1) {
            html += `<li class="page-item"><a class="page-link" href="#" data-page="1">1</a></li>`;
            if (startPage > 2) {
                html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            html += `
                <li class="page-item ${i === this.currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
            }
            html += `<li class="page-item"><a class="page-link" href="#" data-page="${totalPages}">${totalPages}</a></li>`;
        }
        
        // Next button
        html += `
            <li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${this.currentPage + 1}">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </li>
        `;
        
        pagination.innerHTML = html;
        
        // Add event listeners
        pagination.querySelectorAll('.page-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = parseInt(link.getAttribute('data-page'));
                if (page && page !== this.currentPage) {
                    this.goToPage(page);
                }
            });
        });
    }
    
    /**
     * Go to specific page
     */
    goToPage(page) {
        this.currentPage = page;
        this.renderTable();
        this.renderPagination();
        
        // Scroll to top of table
        document.getElementById('findings-table-container').scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
        });
    }
    
    /**
     * Toggle finding selection
     */
    toggleFindingSelection(findingId, selected) {
        if (selected) {
            this.selectedFindings.add(findingId);
        } else {
            this.selectedFindings.delete(findingId);
        }
        
        this.updateSelectionUI();
    }
    
    /**
     * Toggle select all
     */
    toggleSelectAll(selectAll) {
        const pageStartIndex = (this.currentPage - 1) * this.itemsPerPage;
        const pageEndIndex = pageStartIndex + this.itemsPerPage;
        const pageFindings = this.filteredFindings.slice(pageStartIndex, pageEndIndex);
        
        pageFindings.forEach(finding => {
            if (selectAll) {
                this.selectedFindings.add(finding.id);
            } else {
                this.selectedFindings.delete(finding.id);
            }
        });
        
        this.updateSelectionUI();
        this.renderTable(); // Re-render to update checkbox states
    }
    
    /**
     * Update selection UI elements
     */
    updateSelectionUI() {
        this.updateSummaryStats();
        
        // Update bulk actions button
        const bulkAutofixBtn = document.getElementById('bulk-autofix-btn');
        if (bulkAutofixBtn) {
            bulkAutofixBtn.disabled = this.selectedFindings.size === 0;
        }
    }
    
    /**
     * Update checkbox states
     */
    updateCheckboxStates() {
        const checkboxes = document.querySelectorAll('.finding-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = this.selectedFindings.has(checkbox.value);
        });
        
        // Update select all checkboxes
        const pageStartIndex = (this.currentPage - 1) * this.itemsPerPage;
        const pageEndIndex = pageStartIndex + this.itemsPerPage;
        const pageFindings = this.filteredFindings.slice(pageStartIndex, pageEndIndex);
        
        const allSelected = pageFindings.length > 0 && 
                           pageFindings.every(f => this.selectedFindings.has(f.id));
        
        ['select-all-checkbox', 'header-select-all'].forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.checked = allSelected;
            }
        });
    }
    
    /**
     * Show bulk auto-fix modal
     */
    showBulkAutofixModal() {
        const modal = new bootstrap.Modal(document.getElementById('bulkAutofixModal'));
        document.getElementById('bulk-fix-count').textContent = this.selectedFindings.size;
        modal.show();
    }
    
    /**
     * Start bulk auto-fix process
     */
    async startBulkAutofix() {
        try {
            const findingIds = Array.from(this.selectedFindings);
            const response = await window.dashboard.apiCall('/api/autofix', {
                method: 'POST',
                body: JSON.stringify({ finding_ids: findingIds })
            });
            
            window.dashboard.showNotification(
                `Auto-fix started for ${findingIds.length} findings`, 
                'success'
            );
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('bulkAutofixModal'));
            modal.hide();
            
            // Clear selection
            this.selectedFindings.clear();
            this.updateSelectionUI();
            this.renderTable();
            
        } catch (error) {
            console.error('Bulk auto-fix failed:', error);
            window.dashboard.showNotification('Failed to start bulk auto-fix', 'error');
        }
    }
    
    /**
     * Export findings
     */
    exportFindings() {
        const format = 'json'; // Could be made configurable
        const data = this.filteredFindings;
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { 
            type: 'application/json' 
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `devsecure-findings-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
    }
    
    /**
     * Show loading state
     */
    showLoading(show = true) {
        const loading = document.getElementById('findings-loading');
        const container = document.getElementById('findings-table-container');
        const empty = document.getElementById('findings-empty');
        
        if (show) {
            if (loading) loading.style.display = 'block';
            if (container) container.style.display = 'none';
            if (empty) empty.style.display = 'none';
        } else {
            if (loading) loading.style.display = 'none';
        }
    }
    
    /**
     * Show table
     */
    showTable() {
        const loading = document.getElementById('findings-loading');
        const container = document.getElementById('findings-table-container');
        const empty = document.getElementById('findings-empty');
        
        if (loading) loading.style.display = 'none';
        if (container) container.style.display = 'block';
        if (empty) empty.style.display = 'none';
    }
    
    /**
     * Show empty state
     */
    showEmptyState() {
        const loading = document.getElementById('findings-loading');
        const container = document.getElementById('findings-table-container');
        const empty = document.getElementById('findings-empty');
        
        if (loading) loading.style.display = 'none';
        if (container) container.style.display = 'none';
        if (empty) empty.style.display = 'block';
    }
    
    /**
     * Utility functions
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    getFileName(filePath) {
        return filePath.split('/').pop() || filePath;
    }
    
    getCvssClass(score) {
        if (score >= 9.0) return 'bg-danger';
        if (score >= 7.0) return 'bg-warning';
        if (score >= 4.0) return 'bg-info';
        return 'bg-secondary';
    }
}

// Global functions for table actions
window.viewFindingDetail = async function(findingId) {
    try {
        const response = await window.dashboard.apiCall(`/api/findings/${findingId}`);
        
        const modal = new bootstrap.Modal(document.getElementById('findingDetailModal'));
        const content = document.getElementById('finding-detail-content');
        
        content.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <h6>Title</h6>
                    <p class="mb-3">${window.findingsManager.escapeHtml(response.title)}</p>
                    
                    <h6>Description</h6>
                    <p class="mb-3">${window.findingsManager.escapeHtml(response.description)}</p>
                    
                    <h6>Vulnerable Code</h6>
                    <div class="code-snippet mb-3">
                        <pre><code>${window.findingsManager.escapeHtml(response.vulnerable_code || 'N/A')}</code></pre>
                    </div>
                    
                    ${response.suggested_fix ? `
                        <h6>Suggested Fix</h6>
                        <div class="code-snippet mb-3">
                            <pre><code>${window.findingsManager.escapeHtml(response.suggested_fix)}</code></pre>
                        </div>
                    ` : ''}
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h6>Details</h6>
                            <table class="table table-sm">
                                <tr><td>Domain</td><td>${window.dashboard.formatDomain(response.domain)}</td></tr>
                                <tr><td>Severity</td><td>${window.dashboard.formatSeverity(response.severity)}</td></tr>
                                <tr><td>File</td><td><small>${window.findingsManager.escapeHtml(response.file_path)}</small></td></tr>
                                <tr><td>Line</td><td>${response.line_start}${response.line_end !== response.line_start ? `-${response.line_end}` : ''}</td></tr>
                                ${response.cwe ? `<tr><td>CWE</td><td><span class="badge bg-info">${response.cwe}</span></td></tr>` : ''}
                                ${response.cvss_score ? `<tr><td>CVSS</td><td><span class="badge bg-warning">${response.cvss_score}</span></td></tr>` : ''}
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        modal.show();
        
    } catch (error) {
        console.error('Failed to load finding details:', error);
        window.dashboard.showNotification('Failed to load finding details', 'error');
    }
};

window.startSingleAutofix = async function(findingId) {
    try {
        const response = await window.dashboard.apiCall('/api/autofix', {
            method: 'POST',
            body: JSON.stringify({ finding_ids: [findingId] })
        });
        
        window.dashboard.showNotification('Auto-fix started for finding', 'success');
        
    } catch (error) {
        console.error('Single auto-fix failed:', error);
        window.dashboard.showNotification('Failed to start auto-fix', 'error');
    }
};

window.markFalsePositive = function(findingId) {
    window.dashboard.showNotification('False positive marked (feature coming soon)', 'info');
};

window.assignFinding = function(findingId) {
    window.dashboard.showNotification('Assignment feature coming soon', 'info');
};

window.addComment = function(findingId) {
    window.dashboard.showNotification('Comment feature coming soon', 'info');
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.findingsManager = new FindingsManager();
});
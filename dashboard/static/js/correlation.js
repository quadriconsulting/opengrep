/**
 * DevSecure Dashboard - Correlation Visualization
 * D3.js-based interactive graph for finding relationships
 */

class CorrelationGraph {
    constructor() {
        this.data = { nodes: [], edges: [] };
        this.filteredData = { nodes: [], edges: [] };
        this.svg = null;
        this.simulation = null;
        this.transform = null;
        this.selectedNode = null;
        
        // Configuration
        this.config = {
            width: 800,
            height: 600,
            nodeRadius: 12,
            linkStrength: 0.5,
            showLabels: true,
            minSeverityFilter: 'HIGH',
            correlationTypeFilter: '',
            domainFocusFilter: '',
            layoutType: 'force'
        };
        
        // Color schemes
        this.colors = {
            severity: {
                CRITICAL: '#dc3545',
                HIGH: '#fd7e14',
                MEDIUM: '#ffc107',
                LOW: '#0dcaf0'
            },
            domain: {
                SAST: '#0d6efd',
                SCA: '#198754',
                SECRETS: '#dc3545',
                IAC: '#ffc107',
                CONTAINERS: '#6f42c1'
            },
            correlation: {
                DUPLICATE: '#6c757d',
                RELATED: '#0d6efd',
                CAUSAL: '#dc3545',
                MITIGATING: '#198754'
            }
        };
        
        this.initializeGraph();
        this.setupEventListeners();
        this.loadCorrelationData();
    }
    
    /**
     * Initialize the D3 graph
     */
    initializeGraph() {
        const container = document.getElementById('correlation-graph-container');
        const svg = d3.select('#correlation-graph');
        
        if (!container || !svg.node()) return;
        
        // Set dimensions
        const rect = container.getBoundingClientRect();
        this.config.width = rect.width;
        this.config.height = rect.height;
        
        svg.attr('width', this.config.width)
           .attr('height', this.config.height);
        
        this.svg = svg;
        
        // Create main group for zoom/pan
        const mainGroup = svg.append('g').attr('class', 'main-group');
        
        // Create layers
        mainGroup.append('g').attr('class', 'links-layer');
        mainGroup.append('g').attr('class', 'nodes-layer');
        mainGroup.append('g').attr('class', 'labels-layer');
        
        // Setup zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                this.transform = event.transform;
                mainGroup.attr('transform', event.transform);
            });
        
        svg.call(zoom);
        
        // Store zoom behavior for external controls
        this.zoom = zoom;
        
        // Initialize simulation
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).strength(this.config.linkStrength))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2))
            .force('collision', d3.forceCollide().radius(this.config.nodeRadius + 5));
    }
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Filter controls
        document.getElementById('correlation-type-filter').addEventListener('change', (e) => {
            this.config.correlationTypeFilter = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('min-severity-filter').addEventListener('change', (e) => {
            this.config.minSeverityFilter = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('domain-focus-filter').addEventListener('change', (e) => {
            this.config.domainFocusFilter = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('layout-type').addEventListener('change', (e) => {
            this.config.layoutType = e.target.value;
            this.updateLayout();
        });
        
        // Range controls
        document.getElementById('node-size-range').addEventListener('input', (e) => {
            this.config.nodeRadius = parseInt(e.target.value);
            this.updateNodeSizes();
        });
        
        document.getElementById('link-strength-range').addEventListener('input', (e) => {
            this.config.linkStrength = parseFloat(e.target.value);
            this.updateLinkStrength();
        });
        
        // Show labels checkbox
        document.getElementById('show-labels-checkbox').addEventListener('change', (e) => {
            this.config.showLabels = e.target.checked;
            this.toggleLabels();
        });
        
        // Zoom controls
        document.getElementById('zoom-in-btn').addEventListener('click', () => {
            this.zoomIn();
        });
        
        document.getElementById('zoom-out-btn').addEventListener('click', () => {
            this.zoomOut();
        });
        
        document.getElementById('fit-view-btn').addEventListener('click', () => {
            this.fitToView();
        });
        
        document.getElementById('reset-view-btn').addEventListener('click', () => {
            this.resetView();
        });
        
        // Analyze button
        document.getElementById('analyze-btn').addEventListener('click', () => {
            this.runCorrelationAnalysis();
        });
        
        // Close details panel
        document.getElementById('close-details-btn').addEventListener('click', () => {
            this.hideNodeDetails();
        });
        
        // Window resize
        window.addEventListener('resize', () => {
            this.handleResize();
        });
    }
    
    /**
     * Load correlation data from API
     */
    async loadCorrelationData() {
        try {
            this.showLoading(true);
            
            const response = await window.dashboard.apiCall('/api/correlation');
            this.data = {
                nodes: response.nodes || [],
                edges: response.edges || []
            };
            
            // Update statistics
            this.updateStatistics(response.statistics || {});
            
            if (this.data.nodes.length === 0) {
                this.showEmptyState();
            } else {
                this.applyFilters();
            }
            
        } catch (error) {
            console.error('Failed to load correlation data:', error);
            window.dashboard.showNotification('Failed to load correlation data', 'error');
            this.showEmptyState();
        } finally {
            this.showLoading(false);
        }
    }
    
    /**
     * Apply current filters to data
     */
    applyFilters() {
        let filteredNodes = [...this.data.nodes];
        let filteredEdges = [...this.data.edges];
        
        // Filter by minimum severity
        if (this.config.minSeverityFilter) {
            const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
            const minLevel = severityOrder[this.config.minSeverityFilter];
            
            filteredNodes = filteredNodes.filter(node => 
                severityOrder[node.severity] >= minLevel
            );
        }
        
        // Filter by domain focus
        if (this.config.domainFocusFilter) {
            filteredNodes = filteredNodes.filter(node => 
                node.domain === this.config.domainFocusFilter
            );
        }
        
        // Filter edges based on remaining nodes
        const nodeIds = new Set(filteredNodes.map(n => n.id));
        filteredEdges = filteredEdges.filter(edge => 
            nodeIds.has(edge.source) && nodeIds.has(edge.target)
        );
        
        // Filter by correlation type
        if (this.config.correlationTypeFilter) {
            filteredEdges = filteredEdges.filter(edge => 
                edge.type === this.config.correlationTypeFilter
            );
        }
        
        this.filteredData = {
            nodes: filteredNodes,
            edges: filteredEdges
        };
        
        if (this.filteredData.nodes.length === 0) {
            this.showEmptyState();
        } else {
            this.renderGraph();
        }
    }
    
    /**
     * Render the correlation graph
     */
    renderGraph() {
        if (!this.svg || !this.simulation) return;
        
        this.showGraph();
        
        // Prepare data for D3
        const nodes = this.filteredData.nodes.map(d => ({...d}));
        const links = this.filteredData.edges.map(d => ({...d}));
        
        // Update simulation
        this.simulation.nodes(nodes);
        this.simulation.force('link').links(links);
        
        // Render links
        this.renderLinks(links);
        
        // Render nodes
        this.renderNodes(nodes);
        
        // Render labels
        if (this.config.showLabels) {
            this.renderLabels(nodes);
        }
        
        // Restart simulation
        this.simulation.alpha(1).restart();
    }
    
    /**
     * Render graph links
     */
    renderLinks(links) {
        const linksLayer = this.svg.select('.links-layer');
        
        const link = linksLayer.selectAll('.link')
            .data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);
        
        link.exit().remove();
        
        const linkEnter = link.enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke', d => this.colors.correlation[d.type] || '#999')
            .attr('stroke-width', d => Math.sqrt(d.weight || 1) * 2)
            .attr('stroke-opacity', 0.6);
        
        link.merge(linkEnter)
            .attr('stroke', d => this.colors.correlation[d.type] || '#999')
            .attr('stroke-width', d => Math.sqrt(d.weight || 1) * 2);
        
        // Update simulation link positions
        this.simulation.on('tick', () => {
            linksLayer.selectAll('.link')
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
                
            this.updateNodePositions();
            this.updateLabelPositions();
        });
    }
    
    /**
     * Render graph nodes
     */
    renderNodes(nodes) {
        const nodesLayer = this.svg.select('.nodes-layer');
        
        const node = nodesLayer.selectAll('.node')
            .data(nodes, d => d.id);
        
        node.exit().remove();
        
        const nodeEnter = node.enter()
            .append('circle')
            .attr('class', 'node')
            .attr('r', this.config.nodeRadius)
            .attr('fill', d => this.colors.severity[d.severity] || '#999')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .call(d3.drag()
                .on('start', (event, d) => this.dragStarted(event, d))
                .on('drag', (event, d) => this.dragged(event, d))
                .on('end', (event, d) => this.dragEnded(event, d)))
            .on('click', (event, d) => this.nodeClicked(event, d))
            .on('mouseover', (event, d) => this.nodeMouseOver(event, d))
            .on('mouseout', (event, d) => this.nodeMouseOut(event, d));
        
        node.merge(nodeEnter)
            .attr('r', this.config.nodeRadius)
            .attr('fill', d => this.colors.severity[d.severity] || '#999');
    }
    
    /**
     * Render node labels
     */
    renderLabels(nodes) {
        const labelsLayer = this.svg.select('.labels-layer');
        
        const label = labelsLayer.selectAll('.node-label')
            .data(nodes, d => d.id);
        
        label.exit().remove();
        
        const labelEnter = label.enter()
            .append('text')
            .attr('class', 'node-label')
            .attr('text-anchor', 'middle')
            .attr('dy', '.35em')
            .style('font-size', '10px')
            .style('font-weight', 'bold')
            .style('fill', '#333')
            .style('pointer-events', 'none')
            .text(d => this.truncateText(d.title, 15));
        
        label.merge(labelEnter)
            .text(d => this.truncateText(d.title, 15));
    }
    
    /**
     * Update node positions during simulation
     */
    updateNodePositions() {
        this.svg.selectAll('.node')
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
    }
    
    /**
     * Update label positions during simulation
     */
    updateLabelPositions() {
        if (!this.config.showLabels) return;
        
        this.svg.selectAll('.node-label')
            .attr('x', d => d.x)
            .attr('y', d => d.y + this.config.nodeRadius + 15);
    }
    
    /**
     * Node drag handlers
     */
    dragStarted(event, d) {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    dragEnded(event, d) {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    /**
     * Node click handler
     */
    nodeClicked(event, d) {
        this.selectedNode = d;
        this.highlightNode(d);
        this.showNodeDetails(d);
    }
    
    /**
     * Node mouse over handler
     */
    nodeMouseOver(event, d) {
        const tooltip = document.getElementById('graph-tooltip');
        if (tooltip) {
            tooltip.innerHTML = `
                <strong>${d.title}</strong><br>
                Domain: ${d.domain}<br>
                Severity: ${d.severity}<br>
                File: ${d.file_path}
            `;
            tooltip.style.display = 'block';
            tooltip.style.left = (event.pageX + 10) + 'px';
            tooltip.style.top = (event.pageY - 10) + 'px';
        }
        
        // Highlight connected nodes
        this.highlightConnectedNodes(d);
    }
    
    /**
     * Node mouse out handler
     */
    nodeMouseOut(event, d) {
        const tooltip = document.getElementById('graph-tooltip');
        if (tooltip) {
            tooltip.style.display = 'none';
        }
        
        // Remove highlight if not selected
        if (this.selectedNode !== d) {
            this.removeHighlight();
        }
    }
    
    /**
     * Highlight a node and its connections
     */
    highlightNode(node) {
        this.svg.selectAll('.node')
            .style('opacity', d => d === node ? 1 : 0.3);
            
        this.svg.selectAll('.link')
            .style('opacity', d => 
                (d.source === node || d.target === node) ? 1 : 0.1
            );
    }
    
    /**
     * Highlight connected nodes
     */
    highlightConnectedNodes(node) {
        const connectedNodes = new Set([node]);
        
        this.filteredData.edges.forEach(edge => {
            if (edge.source === node || edge.source.id === node.id) {
                connectedNodes.add(edge.target);
            }
            if (edge.target === node || edge.target.id === node.id) {
                connectedNodes.add(edge.source);
            }
        });
        
        this.svg.selectAll('.node')
            .style('opacity', d => connectedNodes.has(d) ? 1 : 0.3);
            
        this.svg.selectAll('.link')
            .style('opacity', d => 
                connectedNodes.has(d.source) && connectedNodes.has(d.target) ? 1 : 0.1
            );
    }
    
    /**
     * Remove highlighting
     */
    removeHighlight() {
        this.svg.selectAll('.node').style('opacity', 1);
        this.svg.selectAll('.link').style('opacity', 0.6);
    }
    
    /**
     * Show node details panel
     */
    showNodeDetails(node) {
        const panel = document.getElementById('node-details-panel');
        const content = document.getElementById('node-details-content');
        
        if (!panel || !content) return;
        
        content.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6>Finding Information</h6>
                    <table class="table table-sm">
                        <tr><td>Title</td><td>${this.escapeHtml(node.title)}</td></tr>
                        <tr><td>Domain</td><td>${window.dashboard.formatDomain(node.domain)}</td></tr>
                        <tr><td>Severity</td><td>${window.dashboard.formatSeverity(node.severity)}</td></tr>
                        <tr><td>File</td><td><small>${this.escapeHtml(node.file_path)}</small></td></tr>
                        <tr><td>Line</td><td>${node.line || 'N/A'}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Correlations</h6>
                    <div id="node-correlations">
                        ${this.renderNodeCorrelations(node)}
                    </div>
                </div>
            </div>
        `;
        
        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth' });
    }
    
    /**
     * Render correlations for a node
     */
    renderNodeCorrelations(node) {
        const correlations = this.filteredData.edges.filter(edge => 
            edge.source === node || edge.target === node || 
            edge.source.id === node.id || edge.target.id === node.id
        );
        
        if (correlations.length === 0) {
            return '<p class="text-muted">No correlations found</p>';
        }
        
        return correlations.map(edge => {
            const otherNode = (edge.source === node || edge.source.id === node.id) ? 
                              edge.target : edge.source;
            
            return `
                <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                    <div>
                        <strong>${edge.type}</strong><br>
                        <small>${this.escapeHtml(otherNode.title || 'Unknown')}</small>
                    </div>
                    <div>
                        ${window.dashboard.formatSeverity(otherNode.severity || 'LOW')}
                    </div>
                </div>
            `;
        }).join('');
    }
    
    /**
     * Hide node details panel
     */
    hideNodeDetails() {
        const panel = document.getElementById('node-details-panel');
        if (panel) {
            panel.style.display = 'none';
        }
        
        this.selectedNode = null;
        this.removeHighlight();
    }
    
    /**
     * Update layout based on selected type
     */
    updateLayout() {
        if (!this.simulation) return;
        
        switch (this.config.layoutType) {
            case 'circle':
                this.applyCircularLayout();
                break;
            case 'hierarchy':
                this.applyHierarchicalLayout();
                break;
            case 'cluster':
                this.applyClusterLayout();
                break;
            default:
                this.applyForceLayout();
        }
    }
    
    /**
     * Apply force-directed layout
     */
    applyForceLayout() {
        this.simulation
            .force('link', d3.forceLink().id(d => d.id).strength(this.config.linkStrength))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2))
            .alpha(1).restart();
    }
    
    /**
     * Apply circular layout
     */
    applyCircularLayout() {
        const nodes = this.filteredData.nodes;
        const radius = Math.min(this.config.width, this.config.height) / 3;
        const centerX = this.config.width / 2;
        const centerY = this.config.height / 2;
        
        nodes.forEach((node, i) => {
            const angle = (i / nodes.length) * 2 * Math.PI;
            node.fx = centerX + radius * Math.cos(angle);
            node.fy = centerY + radius * Math.sin(angle);
        });
        
        this.simulation.alpha(0.3).restart();
    }
    
    /**
     * Apply hierarchical layout
     */
    applyHierarchicalLayout() {
        // Simple hierarchy based on severity
        const severityLevels = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        const levelHeight = this.config.height / 5;
        
        this.filteredData.nodes.forEach((node, i) => {
            const level = severityLevels[node.severity] || 3;
            node.fx = (i % 10) * (this.config.width / 10) + 50;
            node.fy = level * levelHeight + 100;
        });
        
        this.simulation.alpha(0.3).restart();
    }
    
    /**
     * Apply cluster layout
     */
    applyClusterLayout() {
        // Cluster by domain
        const domains = [...new Set(this.filteredData.nodes.map(n => n.domain))];
        const clusterRadius = 100;
        const clusterCenters = {};
        
        // Calculate cluster centers
        domains.forEach((domain, i) => {
            const angle = (i / domains.length) * 2 * Math.PI;
            clusterCenters[domain] = {
                x: this.config.width / 2 + Math.cos(angle) * 150,
                y: this.config.height / 2 + Math.sin(angle) * 150
            };
        });
        
        // Position nodes around cluster centers
        this.filteredData.nodes.forEach(node => {
            const center = clusterCenters[node.domain];
            if (center) {
                const angle = Math.random() * 2 * Math.PI;
                const distance = Math.random() * clusterRadius;
                node.fx = center.x + Math.cos(angle) * distance;
                node.fy = center.y + Math.sin(angle) * distance;
            }
        });
        
        this.simulation.alpha(0.3).restart();
    }
    
    /**
     * Update node sizes
     */
    updateNodeSizes() {
        this.svg.selectAll('.node')
            .attr('r', this.config.nodeRadius);
            
        this.simulation.force('collision')
            .radius(this.config.nodeRadius + 5)
            .alpha(0.3).restart();
    }
    
    /**
     * Update link strength
     */
    updateLinkStrength() {
        this.simulation.force('link')
            .strength(this.config.linkStrength)
            .alpha(0.3).restart();
    }
    
    /**
     * Toggle labels visibility
     */
    toggleLabels() {
        const labels = this.svg.selectAll('.node-label');
        
        if (this.config.showLabels) {
            labels.style('opacity', 1);
        } else {
            labels.style('opacity', 0);
        }
    }
    
    /**
     * Zoom controls
     */
    zoomIn() {
        this.svg.transition().call(this.zoom.scaleBy, 1.5);
    }
    
    zoomOut() {
        this.svg.transition().call(this.zoom.scaleBy, 1 / 1.5);
    }
    
    fitToView() {
        if (this.filteredData.nodes.length === 0) return;
        
        const bounds = this.calculateBounds();
        const dx = bounds.x[1] - bounds.x[0];
        const dy = bounds.y[1] - bounds.y[0];
        const x = (bounds.x[0] + bounds.x[1]) / 2;
        const y = (bounds.y[0] + bounds.y[1]) / 2;
        const scale = Math.min(8, 0.9 / Math.max(dx / this.config.width, dy / this.config.height));
        const translate = [this.config.width / 2 - scale * x, this.config.height / 2 - scale * y];
        
        this.svg.transition()
            .call(this.zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
    }
    
    resetView() {
        this.svg.transition()
            .call(this.zoom.transform, d3.zoomIdentity);
    }
    
    /**
     * Calculate bounds of current nodes
     */
    calculateBounds() {
        const xs = this.filteredData.nodes.map(d => d.x);
        const ys = this.filteredData.nodes.map(d => d.y);
        
        return {
            x: [Math.min(...xs), Math.max(...xs)],
            y: [Math.min(...ys), Math.max(...ys)]
        };
    }
    
    /**
     * Run correlation analysis
     */
    async runCorrelationAnalysis() {
        const modal = new bootstrap.Modal(document.getElementById('correlationAnalysisModal'));
        modal.show();
        
        // Simulate analysis progress
        const progressBar = document.getElementById('analysis-progress');
        const statusText = document.getElementById('analysis-status');
        
        const stages = [
            'Initializing correlation engine...',
            'Analyzing code patterns...',
            'Identifying duplicate findings...',
            'Finding causal relationships...',
            'Calculating risk correlations...',
            'Generating correlation graph...'
        ];
        
        for (let i = 0; i < stages.length; i++) {
            statusText.textContent = stages[i];
            progressBar.style.width = `${((i + 1) / stages.length) * 100}%`;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
        // Close modal and reload data
        modal.hide();
        this.loadCorrelationData();
    }
    
    /**
     * Update statistics display
     */
    updateStatistics(stats) {
        const elements = {
            'total-correlations': stats.total_correlations || 0,
            'duplicate-groups': stats.duplicate_groups || 0,
            'related-chains': stats.related_chains || 0,
            'risk-clusters': stats.risk_clusters || 0
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                window.dashboard.animateCounter(element, parseInt(element.textContent) || 0, value);
            }
        });
    }
    
    /**
     * Handle window resize
     */
    handleResize() {
        const container = document.getElementById('correlation-graph-container');
        if (!container) return;
        
        const rect = container.getBoundingClientRect();
        this.config.width = rect.width;
        this.config.height = rect.height;
        
        this.svg.attr('width', this.config.width)
               .attr('height', this.config.height);
        
        if (this.simulation) {
            this.simulation.force('center', 
                d3.forceCenter(this.config.width / 2, this.config.height / 2)
            ).alpha(0.3).restart();
        }
    }
    
    /**
     * Show loading state
     */
    showLoading(show = true) {
        const loading = document.getElementById('correlation-loading');
        const container = document.getElementById('correlation-graph-container');
        const empty = document.getElementById('correlation-empty');
        
        if (show) {
            if (loading) loading.style.display = 'block';
            if (container) container.style.display = 'none';
            if (empty) empty.style.display = 'none';
        } else {
            if (loading) loading.style.display = 'none';
        }
    }
    
    /**
     * Show graph
     */
    showGraph() {
        const loading = document.getElementById('correlation-loading');
        const container = document.getElementById('correlation-graph-container');
        const empty = document.getElementById('correlation-empty');
        
        if (loading) loading.style.display = 'none';
        if (container) container.style.display = 'block';
        if (empty) empty.style.display = 'none';
    }
    
    /**
     * Show empty state
     */
    showEmptyState() {
        const loading = document.getElementById('correlation-loading');
        const container = document.getElementById('correlation-graph-container');
        const empty = document.getElementById('correlation-empty');
        
        if (loading) loading.style.display = 'none';
        if (container) container.style.display = 'none';
        if (empty) empty.style.display = 'block';
    }
    
    /**
     * Utility functions
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    truncateText(text, maxLength) {
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.correlationGraph = new CorrelationGraph();
});
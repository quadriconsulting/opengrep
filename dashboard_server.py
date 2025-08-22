#!/usr/bin/env python3
"""
DevSecure Web Dashboard Server
============================

Flask-based web interface for the DevSecure unified security platform.
Provides real-time visualization, scan management, and findings analysis.
"""

import asyncio
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import yaml

# Import our DevSecure platform
from devsecure import (
    DevSecureUnifiedPlatform, SecurityDomain, UnifiedFinding,
    Severity, FixConfidence, FindingCorrelationType
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DevSecureDashboardServer:
    """Flask web server for DevSecure dashboard"""
    
    def __init__(self, config_path: str = "config.yaml", port: int = 5000):
        self.app = Flask(__name__, 
                        template_folder='dashboard/templates',
                        static_folder='dashboard/static')
        self.app.config['SECRET_KEY'] = 'devsecure-dashboard-secret-key'
        
        # Enable CORS for API calls
        CORS(self.app, origins="*")
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize DevSecure platform
        self.platform = DevSecureUnifiedPlatform(config_path)
        self.port = port
        
        # Dashboard state
        self.active_scans = {}
        self.scan_history = []
        self.real_time_metrics = {
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'auto_fixed': 0,
            'pending_fixes': 0,
            'scan_status': 'idle'
        }
        
        self._setup_routes()
        self._setup_socketio_events()
        
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return render_template('dashboard.html')
            
        @self.app.route('/findings')
        def findings_page():
            """Findings analysis page"""
            return render_template('findings.html')
            
        @self.app.route('/scans')
        def scans_page():
            """Scan management page"""
            return render_template('scans.html')
            
        @self.app.route('/correlation')
        def correlation_page():
            """Finding correlation analysis page"""
            return render_template('correlation.html')
            
        @self.app.route('/autofix')
        def autofix_page():
            """Auto-fix management page"""
            return render_template('autofix.html')
            
        @self.app.route('/config')
        def config_page():
            """Configuration page"""
            return render_template('config.html')
            
        # API Routes
        @self.app.route('/api/metrics')
        def get_metrics():
            """Get current security metrics"""
            return jsonify(self.real_time_metrics)
            
        @self.app.route('/api/findings')
        def get_findings():
            """Get all findings with optional filtering"""
            domain = request.args.get('domain')
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))
            
            findings = self._get_filtered_findings(domain, severity, limit, offset)
            return jsonify({
                'findings': [self._finding_to_dict(f) for f in findings],
                'total': len(findings),
                'offset': offset,
                'limit': limit
            })
            
        @self.app.route('/api/findings/<finding_id>')
        def get_finding_detail(finding_id):
            """Get detailed information about a specific finding"""
            finding = self._get_finding_by_id(finding_id)
            if finding:
                return jsonify(self._finding_to_dict(finding, detailed=True))
            return jsonify({'error': 'Finding not found'}), 404
            
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            """Start a new security scan"""
            data = request.get_json()
            project_path = data.get('project_path')
            domains = data.get('domains', ['SAST', 'SCA', 'SECRETS', 'IAC', 'CONTAINERS'])
            
            if not project_path:
                return jsonify({'error': 'project_path is required'}), 400
                
            scan_id = self._start_background_scan(project_path, domains)
            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'message': f'Scan started for {project_path}'
            })
            
        @self.app.route('/api/scan/<scan_id>/status')
        def get_scan_status(scan_id):
            """Get status of a running scan"""
            scan = self.active_scans.get(scan_id)
            if scan:
                return jsonify({
                    'scan_id': scan_id,
                    'status': scan['status'],
                    'progress': scan.get('progress', 0),
                    'current_domain': scan.get('current_domain'),
                    'findings_count': scan.get('findings_count', 0),
                    'start_time': scan.get('start_time'),
                    'estimated_completion': scan.get('estimated_completion')
                })
            return jsonify({'error': 'Scan not found'}), 404
            
        @self.app.route('/api/autofix', methods=['POST'])
        def trigger_autofix():
            """Trigger auto-fix for selected findings"""
            data = request.get_json()
            finding_ids = data.get('finding_ids', [])
            
            if not finding_ids:
                return jsonify({'error': 'finding_ids is required'}), 400
                
            fix_id = self._start_autofix_process(finding_ids)
            return jsonify({
                'fix_id': fix_id,
                'status': 'started',
                'message': f'Auto-fix started for {len(finding_ids)} findings'
            })
            
        @self.app.route('/api/correlation')
        def get_correlation_data():
            """Get finding correlation data for visualization"""
            correlations = self._get_finding_correlations()
            return jsonify({
                'nodes': correlations['nodes'],
                'edges': correlations['edges'],
                'statistics': correlations['statistics']
            })
            
        @self.app.route('/api/config', methods=['GET', 'POST'])
        def handle_config():
            """Get or update configuration"""
            if request.method == 'GET':
                return jsonify(self._get_config())
            else:
                data = request.get_json()
                success = self._update_config(data)
                if success:
                    return jsonify({'message': 'Configuration updated successfully'})
                return jsonify({'error': 'Failed to update configuration'}), 500
                
    def _setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client connected: {request.sid}")
            emit('connected', {'message': 'Connected to DevSecure Dashboard'})
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client disconnected: {request.sid}")
            
        @self.socketio.on('join_scan')
        def handle_join_scan(data):
            scan_id = data.get('scan_id')
            if scan_id:
                join_room(scan_id)
                logger.info(f"Client {request.sid} joined scan room {scan_id}")
                
        @self.socketio.on('leave_scan')
        def handle_leave_scan(data):
            scan_id = data.get('scan_id')
            if scan_id:
                leave_room(scan_id)
                logger.info(f"Client {request.sid} left scan room {scan_id}")
                
    def _start_background_scan(self, project_path: str, domains: List[str]) -> str:
        """Start a background security scan"""
        scan_id = f"scan_{int(time.time() * 1000)}"
        
        scan_data = {
            'scan_id': scan_id,
            'project_path': project_path,
            'domains': domains,
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now().isoformat(),
            'findings_count': 0
        }
        
        self.active_scans[scan_id] = scan_data
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_scan_async,
            args=(scan_id, project_path, domains)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
        
    def _run_scan_async(self, scan_id: str, project_path: str, domains: List[str]):
        """Run security scan asynchronously"""
        try:
            scan_data = self.active_scans[scan_id]
            scan_data['status'] = 'running'
            
            # Emit scan started event
            self.socketio.emit('scan_update', {
                'scan_id': scan_id,
                'status': 'running',
                'message': 'Scan started'
            }, room=scan_id)
            
            # Convert domain strings to SecurityDomain enums
            domain_enums = []
            for domain in domains:
                try:
                    domain_enums.append(SecurityDomain[domain.upper()])
                except KeyError:
                    logger.warning(f"Unknown domain: {domain}")
                    
            # Run the actual scan
            results = self.platform.run_unified_scan(
                project_path=project_path,
                domains=domain_enums,
                output_format='json',
                progress_callback=lambda progress, domain: self._emit_scan_progress(
                    scan_id, progress, domain
                )
            )
            
            # Update scan results
            scan_data['status'] = 'completed'
            scan_data['progress'] = 100
            scan_data['findings_count'] = len(results.get('unified_findings', []))
            scan_data['end_time'] = datetime.now().isoformat()
            scan_data['results'] = results
            
            # Update real-time metrics
            self._update_metrics_from_results(results)
            
            # Emit completion event
            self.socketio.emit('scan_complete', {
                'scan_id': scan_id,
                'status': 'completed',
                'findings_count': scan_data['findings_count'],
                'message': 'Scan completed successfully'
            }, room=scan_id)
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan_data['status'] = 'failed'
            scan_data['error'] = str(e)
            scan_data['end_time'] = datetime.now().isoformat()
            
            self.socketio.emit('scan_error', {
                'scan_id': scan_id,
                'error': str(e),
                'message': 'Scan failed'
            }, room=scan_id)
            
    def _emit_scan_progress(self, scan_id: str, progress: int, domain: str):
        """Emit scan progress update"""
        scan_data = self.active_scans.get(scan_id)
        if scan_data:
            scan_data['progress'] = progress
            scan_data['current_domain'] = domain
            
            self.socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': progress,
                'current_domain': domain
            }, room=scan_id)
            
    def _update_metrics_from_results(self, results: Dict[str, Any]):
        """Update real-time metrics from scan results"""
        findings = results.get('unified_findings', [])
        
        self.real_time_metrics['total_findings'] = len(findings)
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        self.real_time_metrics['critical_findings'] = severity_counts['CRITICAL']
        self.real_time_metrics['high_findings'] = severity_counts['HIGH']
        self.real_time_metrics['medium_findings'] = severity_counts['MEDIUM']
        self.real_time_metrics['low_findings'] = severity_counts['LOW']
        
        # Update auto-fix metrics
        auto_fix_results = results.get('auto_fix_results', {})
        self.real_time_metrics['auto_fixed'] = len(auto_fix_results.get('applied_fixes', []))
        self.real_time_metrics['pending_fixes'] = len(auto_fix_results.get('pending_fixes', []))
        
        # Emit metrics update
        self.socketio.emit('metrics_update', self.real_time_metrics)
        
    def _get_filtered_findings(self, domain: Optional[str], severity: Optional[str], 
                             limit: int, offset: int) -> List[UnifiedFinding]:
        """Get filtered findings from the platform"""
        # This would integrate with the actual platform data storage
        # For now, return sample data
        return []
        
    def _get_finding_by_id(self, finding_id: str) -> Optional[UnifiedFinding]:
        """Get finding by ID"""
        # This would query the actual platform data storage
        return None
        
    def _finding_to_dict(self, finding: UnifiedFinding, detailed: bool = False) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization"""
        base_dict = {
            'id': finding.id,
            'domain': finding.domain.value,
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity.value,
            'confidence': finding.confidence.value,
            'file_path': finding.file_path,
            'line_start': finding.line_start,
            'line_end': finding.line_end,
            'cwe': finding.cwe,
            'owasp': finding.owasp,
            'cvss_score': finding.cvss_score
        }
        
        if detailed:
            base_dict.update({
                'vulnerable_code': finding.vulnerable_code,
                'context_before': finding.context_before,
                'context_after': finding.context_after,
                'suggested_fix': getattr(finding, 'suggested_fix', None),
                'fix_explanation': getattr(finding, 'fix_explanation', None)
            })
            
        return base_dict
        
    def _start_autofix_process(self, finding_ids: List[str]) -> str:
        """Start auto-fix process for selected findings"""
        fix_id = f"fix_{int(time.time() * 1000)}"
        
        # This would integrate with the platform's auto-fix engine
        # For now, return a mock fix ID
        
        return fix_id
        
    def _get_finding_correlations(self) -> Dict[str, Any]:
        """Get finding correlation data for visualization"""
        # This would query the platform's correlation engine
        return {
            'nodes': [],
            'edges': [],
            'statistics': {
                'total_correlations': 0,
                'duplicate_groups': 0,
                'related_chains': 0
            }
        }
        
    def _get_config(self) -> Dict[str, Any]:
        """Get current configuration"""
        try:
            with open(self.platform.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
            
    def _update_config(self, config_data: Dict[str, Any]) -> bool:
        """Update configuration"""
        try:
            with open(self.platform.config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)
            return True
        except Exception as e:
            logger.error(f"Failed to update config: {e}")
            return False
            
    def run(self, debug: bool = False, host: str = '0.0.0.0'):
        """Run the dashboard server"""
        logger.info(f"Starting DevSecure Dashboard on {host}:{self.port}")
        self.socketio.run(self.app, debug=debug, host=host, port=self.port)


def main():
    """Main entry point for dashboard server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DevSecure Web Dashboard')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--host', default='0.0.0.0', help='Server host')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create and run dashboard server
    dashboard = DevSecureDashboardServer(
        config_path=args.config,
        port=args.port
    )
    
    dashboard.run(debug=args.debug, host=args.host)


if __name__ == '__main__':
    main()
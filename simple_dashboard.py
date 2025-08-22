#!/usr/bin/env python3
"""
DevSecure Web Dashboard - Standalone Testing Version
==================================================

Simplified Flask-based web interface for testing the dashboard UI
without heavy AI/ML dependencies.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleDashboardServer:
    """Simplified Flask web server for DevSecure dashboard testing"""
    
    def __init__(self, config_path: str = "config.yaml", port: int = 5000):
        self.app = Flask(__name__, 
                        template_folder='dashboard/templates',
                        static_folder='dashboard/static')
        self.app.config['SECRET_KEY'] = 'devsecure-dashboard-secret-key'
        
        # Enable CORS for API calls
        CORS(self.app, origins="*")
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self.port = port
        self.config_path = config_path
        
        # Mock data for testing
        self.mock_metrics = {
            'total_findings': 47,
            'critical_findings': 8,
            'high_findings': 12,
            'medium_findings': 18,
            'low_findings': 9,
            'auto_fixed': 23,
            'pending_fixes': 7,
            'scan_status': 'idle'
        }
        
        self.mock_findings = [
            {
                'id': 'finding_001',
                'title': 'SQL Injection vulnerability in user authentication',
                'description': 'Unsafe string concatenation allows SQL injection attacks',
                'severity': 'CRITICAL',
                'domain': 'SAST',
                'file_path': '/src/auth/login.py',
                'line_start': 45,
                'line_end': 47,
                'cwe': 'CWE-89',
                'cvss_score': 9.1,
                'vulnerable_code': "query = \"SELECT * FROM users WHERE username='\" + username + \"' AND password='\" + password + \"'\"",
                'timestamp': datetime.now().isoformat()
            },
            {
                'id': 'finding_002',
                'title': 'Cross-Site Scripting (XSS) in search functionality',
                'description': 'User input is not properly sanitized before display',
                'severity': 'HIGH',
                'domain': 'SAST',
                'file_path': '/src/search/results.py',
                'line_start': 23,
                'line_end': 23,
                'cwe': 'CWE-79',
                'cvss_score': 7.4,
                'vulnerable_code': "return f\"<h1>Search results for: {query}</h1>\"",
                'timestamp': datetime.now().isoformat()
            },
            {
                'id': 'finding_003',
                'title': 'Hardcoded API key in configuration file',
                'description': 'Sensitive API key is hardcoded in source code',
                'severity': 'CRITICAL',
                'domain': 'SECRETS',
                'file_path': '/config/settings.py',
                'line_start': 12,
                'line_end': 12,
                'cwe': 'CWE-798',
                'cvss_score': 8.8,
                'vulnerable_code': "API_KEY = 'sk-1234567890abcdef'",
                'timestamp': datetime.now().isoformat()
            }
        ]
        
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
            return jsonify(self.mock_metrics)
            
        @self.app.route('/api/findings')
        def get_findings():
            """Get all findings with optional filtering"""
            domain = request.args.get('domain')
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))
            
            findings = self.mock_findings.copy()
            
            # Apply filters
            if domain:
                findings = [f for f in findings if f['domain'] == domain]
            if severity:
                findings = [f for f in findings if f['severity'] == severity]
            
            # Apply pagination
            paginated = findings[offset:offset + limit]
            
            return jsonify({
                'findings': paginated,
                'total': len(findings),
                'offset': offset,
                'limit': limit
            })
            
        @self.app.route('/api/findings/<finding_id>')
        def get_finding_detail(finding_id):
            """Get detailed information about a specific finding"""
            finding = next((f for f in self.mock_findings if f['id'] == finding_id), None)
            if finding:
                return jsonify(finding)
            return jsonify({'error': 'Finding not found'}), 404
            
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            """Start a new security scan"""
            data = request.get_json()
            project_path = data.get('project_path')
            domains = data.get('domains', ['SAST', 'SCA', 'SECRETS', 'IAC', 'CONTAINERS'])
            
            if not project_path:
                return jsonify({'error': 'project_path is required'}), 400
                
            scan_id = f"scan_{int(time.time() * 1000)}"
            
            # Mock successful scan start
            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'message': f'Scan started for {project_path}'
            })
            
        @self.app.route('/api/autofix', methods=['POST'])
        def trigger_autofix():
            """Trigger auto-fix for selected findings"""
            data = request.get_json()
            finding_ids = data.get('finding_ids', [])
            
            if not finding_ids:
                return jsonify({'error': 'finding_ids is required'}), 400
                
            fix_id = f"fix_{int(time.time() * 1000)}"
            
            return jsonify({
                'fix_id': fix_id,
                'status': 'started',
                'message': f'Auto-fix started for {len(finding_ids)} findings'
            })
            
        @self.app.route('/api/correlation')
        def get_correlation_data():
            """Get finding correlation data for visualization"""
            # Mock correlation data
            return jsonify({
                'nodes': [
                    {'id': 'finding_001', 'title': 'SQL Injection', 'severity': 'CRITICAL', 'domain': 'SAST', 'file_path': '/src/auth/login.py'},
                    {'id': 'finding_002', 'title': 'XSS Vulnerability', 'severity': 'HIGH', 'domain': 'SAST', 'file_path': '/src/search/results.py'},
                    {'id': 'finding_003', 'title': 'Hardcoded API Key', 'severity': 'CRITICAL', 'domain': 'SECRETS', 'file_path': '/config/settings.py'}
                ],
                'edges': [
                    {'source': 'finding_001', 'target': 'finding_003', 'type': 'RELATED', 'weight': 0.8},
                    {'source': 'finding_002', 'target': 'finding_001', 'type': 'CAUSAL', 'weight': 0.6}
                ],
                'statistics': {
                    'total_correlations': 2,
                    'duplicate_groups': 0,
                    'related_chains': 1
                }
            })
            
        @self.app.route('/api/config', methods=['GET', 'POST'])
        def handle_config():
            """Get or update configuration"""
            if request.method == 'GET':
                # Return mock configuration
                return jsonify({
                    'general': {
                        'platform_name': 'DevSecure',
                        'max_concurrent_scans': 3,
                        'scan_timeout': 30
                    },
                    'security_engines': {
                        'sast': {'enabled': True},
                        'sca': {'enabled': True},
                        'secrets': {'enabled': True}
                    }
                })
            else:
                # Mock successful update
                return jsonify({'message': 'Configuration updated successfully'})
                
    def _setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client connected: {request.sid}")
            emit('connected', {'message': 'Connected to DevSecure Dashboard'})
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client disconnected: {request.sid}")
            
    def run(self, debug: bool = False, host: str = '0.0.0.0'):
        """Run the dashboard server"""
        logger.info(f"Starting DevSecure Simple Dashboard on {host}:{self.port}")
        self.socketio.run(self.app, debug=debug, host=host, port=self.port, allow_unsafe_werkzeug=True)


def main():
    """Main entry point for simple dashboard server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DevSecure Simple Web Dashboard')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--host', default='0.0.0.0', help='Server host')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create and run dashboard server
    dashboard = SimpleDashboardServer(
        config_path=args.config,
        port=args.port
    )
    
    dashboard.run(debug=args.debug, host=args.host)


if __name__ == '__main__':
    main()
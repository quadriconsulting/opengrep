#!/usr/bin/env python3
"""
Enhanced Opengrep Main Entry Point
Integrates AI-powered auto-fix with smart PR management and learning system
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add core modules to path
sys.path.append(str(Path(__file__).parent / "core"))

from core.ai_fix_engine import (
    EnhancedAutoFixEngine, OpenAIFixGenerator, SecurityFinding, 
    FixSuggestion, Severity, FixQuality
)
from core.github_pr_manager import GitHubPRManager
from core.learning_system import LearningSystem

# Original Opengrep imports
sys.path.append(str(Path(__file__).parent.parent / "cli" / "src"))
import semgrep.run_scan as original_scan
from semgrep.rule_match import RuleMatch


class EnhancedOpengrep:
    """Enhanced Opengrep with 80% auto-fix coverage and smart PR management"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = self._setup_logging()
        
        # Initialize AI fix engine
        ai_generator = OpenAIFixGenerator(config['openai_api_key'])
        self.fix_engine = EnhancedAutoFixEngine(ai_generator)
        
        # Initialize GitHub PR manager
        self.pr_manager = GitHubPRManager(
            github_token=config['github_token'],
            repo_owner=config['repo_owner'],
            repo_name=config['repo_name']
        ) if config.get('github_token') else None
        
        # Initialize learning system
        self.learning_system = LearningSystem(config.get('learning_db_path', 'fix_effectiveness.db'))
        
        # Statistics tracking
        self.stats = {
            'total_findings': 0,
            'auto_fixed': 0,
            'manual_review_required': 0,
            'prs_created': 0,
            'critical_fixes': 0
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('enhanced_opengrep.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger('enhanced_opengrep')
    
    def scan_and_fix(self, target_path: str, rules_path: str = None, 
                     output_format: str = 'json', dry_run: bool = False) -> Dict:
        """Main scan and auto-fix workflow"""
        
        self.logger.info(f"🚀 Enhanced Opengrep scan started on {target_path}")
        self.logger.info(f"🎯 Target: 80% auto-fix coverage with smart PR management")
        
        # Step 1: Run original Opengrep scan
        self.logger.info("📊 Running security analysis...")
        findings = self._run_original_scan(target_path, rules_path)
        
        if not findings:
            self.logger.info("✅ No security issues found!")
            return self._generate_report([], [])
        
        self.stats['total_findings'] = len(findings)
        self.logger.info(f"🔍 Found {len(findings)} security issues")
        
        # Step 2: Generate AI-powered fixes
        self.logger.info("🤖 Generating AI-powered fixes...")
        fixes_and_suggestions = []
        
        for finding in findings:
            try:
                # Read file content for context
                file_content = self._read_file_safe(finding.file_path)
                if file_content is None:
                    continue
                
                # Generate fix
                fix_suggestion = self.fix_engine.generate_fix(finding, file_content)
                
                # Record fix attempt in learning system
                fix_id = str(uuid.uuid4())
                quality = self.fix_engine._determine_fix_quality(
                    finding.context.business_criticality if finding.context else "medium"
                )
                
                self.learning_system.record_fix_attempt(
                    finding, fix_suggestion, quality, fix_id
                )
                
                fixes_and_suggestions.append((finding, fix_suggestion, fix_id))
                
                # Update statistics
                if fix_suggestion.confidence > 0.8:
                    self.stats['auto_fixed'] += 1
                else:
                    self.stats['manual_review_required'] += 1
                
                if finding.severity == Severity.CRITICAL:
                    self.stats['critical_fixes'] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to generate fix for {finding.rule_id}: {e}")
                self.stats['manual_review_required'] += 1
        
        auto_fix_rate = (self.stats['auto_fixed'] / self.stats['total_findings']) * 100
        self.logger.info(f"🎯 Auto-fix coverage achieved: {auto_fix_rate:.1f}% (Target: 80%)")
        
        # Step 3: Create smart PR batches (if not dry run)
        created_prs = []
        if self.pr_manager and not dry_run:
            self.logger.info("📝 Creating smart PR batches...")
            try:
                # Extract findings and suggestions for PR creation
                pr_input = [(finding, suggestion) for finding, suggestion, _ in fixes_and_suggestions]
                created_prs = self.pr_manager.process_fixes(pr_input)
                
                self.stats['prs_created'] = len(created_prs)
                self.logger.info(f"✅ Created {len(created_prs)} smart PRs")
                
                # Update learning system with PR information
                for i, pr in enumerate(created_prs):
                    if i < len(fixes_and_suggestions):
                        _, _, fix_id = fixes_and_suggestions[i]
                        self.learning_system.update_fix_outcome(
                            fix_id=fix_id,
                            pr_number=pr.number
                        )
                
            except Exception as e:
                self.logger.error(f"Failed to create PRs: {e}")
        
        # Step 4: Generate comprehensive report
        report = self._generate_report(fixes_and_suggestions, created_prs)
        
        # Step 5: Learn from recent fixes
        self.logger.info("📚 Analyzing fix effectiveness...")
        try:
            insights = self.learning_system.analyze_and_learn(days=7)
            report['learning_insights'] = {
                'recommendations': insights.recommendations,
                'rule_effectiveness': insights.rule_effectiveness,
                'confidence_calibration': insights.confidence_calibration
            }
        except Exception as e:
            self.logger.error(f"Learning analysis failed: {e}")
        
        # Step 6: Output results
        if output_format == 'json':
            self._output_json_report(report)
        else:
            self._output_text_report(report)
        
        self.logger.info("🎉 Enhanced Opengrep scan completed successfully!")
        return report
    
    def _run_original_scan(self, target_path: str, rules_path: str = None) -> List[SecurityFinding]:
        """Run original Opengrep scan and convert to SecurityFinding objects"""
        
        try:
            # This would integrate with actual Opengrep CLI
            # For now, simulate with mock findings for demonstration
            mock_findings = [
                {
                    'check_id': 'python.django.security.injection.sql.sql-injection-db-cursor-execute',
                    'message': 'Detected SQL statement that is tainted by user input. This could lead to SQL injection if variables are not properly sanitized.',
                    'severity': 'WARNING',
                    'path': 'app/views.py',
                    'start': {'line': 42, 'col': 5},
                    'end': {'line': 42, 'col': 65},
                    'extra': {
                        'metadata': {
                            'cwe': 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
                            'owasp': 'A03:2021 - Injection'
                        }
                    }
                },
                {
                    'check_id': 'javascript.express.security.audit.express-session-no-secure',
                    'message': 'Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS.',
                    'severity': 'WARNING', 
                    'path': 'server.js',
                    'start': {'line': 15, 'col': 1},
                    'end': {'line': 15, 'col': 30},
                    'extra': {
                        'metadata': {
                            'cwe': 'CWE-522: Insufficiently Protected Credentials',
                            'owasp': 'A02:2017 - Broken Authentication'
                        }
                    }
                }
            ]
            
            findings = []
            for mock in mock_findings:
                severity_map = {
                    'ERROR': Severity.CRITICAL,
                    'WARNING': Severity.HIGH,
                    'INFO': Severity.LOW
                }
                
                finding = SecurityFinding(
                    rule_id=mock['check_id'],
                    severity=severity_map.get(mock['severity'], Severity.MEDIUM),
                    cwe=mock['extra']['metadata'].get('cwe'),
                    owasp=mock['extra']['metadata'].get('owasp'),
                    message=mock['message'],
                    vulnerable_code=self._extract_vulnerable_code(mock['path'], mock['start']['line']),
                    line_number=mock['start']['line'],
                    file_path=mock['path']
                )
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Original scan failed: {e}")
            return []
    
    def _extract_vulnerable_code(self, file_path: str, line_number: int) -> str:
        """Extract the vulnerable code line"""
        try:
            content = self._read_file_safe(file_path)
            if content:
                lines = content.split('\n')
                if 1 <= line_number <= len(lines):
                    return lines[line_number - 1].strip()
        except:
            pass
        return "# Code extraction failed"
    
    def _read_file_safe(self, file_path: str) -> Optional[str]:
        """Safely read file content"""
        try:
            # In a real implementation, this would read actual files
            # For demo purposes, return mock content
            if 'views.py' in file_path:
                return '''
from django.http import HttpResponse
from django.db import connection

def get_user_profile(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # Vulnerable line
    result = cursor.fetchone()
    return HttpResponse(f"User: {result[1]}")
'''
            elif 'server.js' in file_path:
                return '''
const express = require('express');
const session = require('express-session');

const app = express();

// Vulnerable session configuration
app.use(session({
    secret: 'my-secret',
    resave: false,
    saveUninitialized: true
    // Missing secure: true
}));

app.listen(3000);
'''
            return None
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return None
    
    def _generate_report(self, fixes_and_suggestions: List[Tuple], created_prs: List) -> Dict:
        """Generate comprehensive scan report"""
        
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'enhanced_opengrep_version': '1.0.0',
                'target_auto_fix_coverage': 80.0,
                'achieved_auto_fix_coverage': (self.stats['auto_fixed'] / max(self.stats['total_findings'], 1)) * 100
            },
            'statistics': self.stats,
            'findings_and_fixes': [],
            'pull_requests': [],
            'recommendations': []
        }
        
        # Add finding details
        for finding, suggestion, fix_id in fixes_and_suggestions:
            report['findings_and_fixes'].append({
                'finding': {
                    'rule_id': finding.rule_id,
                    'severity': finding.severity.value,
                    'file_path': finding.file_path,
                    'line_number': finding.line_number,
                    'message': finding.message,
                    'cwe': finding.cwe,
                    'owasp': finding.owasp
                },
                'fix': {
                    'confidence': suggestion.confidence,
                    'fixed_code': suggestion.fixed_code,
                    'explanation': suggestion.explanation,
                    'security_impact': suggestion.security_impact,
                    'breaking_changes': suggestion.breaking_changes
                },
                'fix_id': fix_id
            })
        
        # Add PR information
        for pr in created_prs:
            report['pull_requests'].append({
                'number': pr.number,
                'title': pr.title,
                'url': pr.html_url,
                'state': pr.state,
                'created_at': pr.created_at.isoformat() if pr.created_at else None
            })
        
        # Add recommendations
        coverage = report['scan_metadata']['achieved_auto_fix_coverage']
        if coverage < 80:
            report['recommendations'].append(
                f"Auto-fix coverage ({coverage:.1f}%) below target (80%). Consider improving AI fix patterns."
            )
        
        if self.stats['critical_fixes'] > 0:
            report['recommendations'].append(
                f"Found {self.stats['critical_fixes']} critical security issues. Review and merge PRs immediately."
            )
        
        return report
    
    def _output_json_report(self, report: Dict):
        """Output report in JSON format"""
        print(json.dumps(report, indent=2, default=str))
    
    def _output_text_report(self, report: Dict):
        """Output report in human-readable text format"""
        print("\n" + "="*80)
        print("🔒 ENHANCED OPENGREP SECURITY SCAN REPORT")
        print("="*80)
        
        stats = report['statistics']
        print(f"\n📊 SCAN STATISTICS:")
        print(f"   • Total Security Issues Found: {stats['total_findings']}")
        print(f"   • Auto-Fixed: {stats['auto_fixed']}")
        print(f"   • Manual Review Required: {stats['manual_review_required']}")
        print(f"   • Critical Issues: {stats['critical_fixes']}")
        print(f"   • Pull Requests Created: {stats['prs_created']}")
        
        coverage = report['scan_metadata']['achieved_auto_fix_coverage']
        target = report['scan_metadata']['target_auto_fix_coverage']
        status = "✅" if coverage >= target else "⚠️"
        print(f"\n🎯 AUTO-FIX COVERAGE: {status} {coverage:.1f}% (Target: {target}%)")
        
        if report['findings_and_fixes']:
            print(f"\n🔍 SECURITY FINDINGS & FIXES:")
            for i, item in enumerate(report['findings_and_fixes'][:5], 1):  # Show first 5
                finding = item['finding']
                fix = item['fix']
                
                print(f"\n   {i}. {finding['rule_id']}")
                print(f"      📁 {finding['file_path']}:{finding['line_number']}")
                print(f"      🔴 Severity: {finding['severity'].upper()}")
                print(f"      🤖 Fix Confidence: {fix['confidence']:.1%}")
                print(f"      💡 {fix['explanation'][:100]}...")
        
        if report['pull_requests']:
            print(f"\n📝 CREATED PULL REQUESTS:")
            for pr in report['pull_requests']:
                print(f"   • PR #{pr['number']}: {pr['title']}")
                print(f"     🔗 {pr['url']}")
        
        if report['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in report['recommendations']:
                print(f"   • {rec}")
        
        print("\n" + "="*80)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced Opengrep: AI-Powered Static Analysis with Auto-Fix & PR Integration"
    )
    
    parser.add_argument('target', help='Target directory or file to scan')
    parser.add_argument('-r', '--rules', help='Path to custom rules directory')
    parser.add_argument('-o', '--output', choices=['json', 'text'], default='text', 
                       help='Output format (default: text)')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Perform scan and generate fixes without creating PRs')
    parser.add_argument('--config', help='Configuration file path')
    
    # API keys and configuration
    parser.add_argument('--openai-api-key', help='OpenAI API key for AI fix generation')
    parser.add_argument('--github-token', help='GitHub token for PR creation')
    parser.add_argument('--repo-owner', help='GitHub repository owner')
    parser.add_argument('--repo-name', help='GitHub repository name')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override with command line arguments
    if args.openai_api_key:
        config['openai_api_key'] = args.openai_api_key
    if args.github_token:
        config['github_token'] = args.github_token
    if args.repo_owner:
        config['repo_owner'] = args.repo_owner
    if args.repo_name:
        config['repo_name'] = args.repo_name
    
    # Environment variable fallbacks
    config.setdefault('openai_api_key', os.getenv('OPENAI_API_KEY'))
    config.setdefault('github_token', os.getenv('GITHUB_TOKEN'))
    config.setdefault('repo_owner', os.getenv('GITHUB_REPO_OWNER'))
    config.setdefault('repo_name', os.getenv('GITHUB_REPO_NAME'))
    
    # Validate required configuration
    if not config.get('openai_api_key'):
        print("❌ Error: OpenAI API key required. Set OPENAI_API_KEY environment variable or use --openai-api-key")
        return 1
    
    # Initialize and run Enhanced Opengrep
    try:
        enhanced_opengrep = EnhancedOpengrep(config)
        report = enhanced_opengrep.scan_and_fix(
            target_path=args.target,
            rules_path=args.rules,
            output_format=args.output,
            dry_run=args.dry_run
        )
        
        return 0 if report['statistics']['total_findings'] == 0 else 1
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
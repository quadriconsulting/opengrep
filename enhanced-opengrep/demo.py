#!/usr/bin/env python3
"""
Enhanced Opengrep Demo Script
Demonstrates 80% auto-fix coverage with smart PR management
"""

import json
import os
import sys
from pathlib import Path

# Set up environment for demo
os.environ.setdefault('OPENAI_API_KEY', 'demo-key-replace-with-real')
os.environ.setdefault('GITHUB_TOKEN', 'demo-token-replace-with-real')
os.environ.setdefault('GITHUB_REPO_OWNER', 'your-org')
os.environ.setdefault('GITHUB_REPO_NAME', 'your-repo')

# Import our enhanced system
sys.path.append(str(Path(__file__).parent))
from enhanced_opengrep_main import EnhancedOpengrep


def create_sample_vulnerable_files():
    """Create sample vulnerable files for demonstration"""
    
    # Create demo directory structure
    demo_dir = Path("demo_project")
    demo_dir.mkdir(exist_ok=True)
    
    # Python Django example with SQL injection
    django_view = '''
from django.http import HttpResponse, HttpRequest
from django.db import connection
from django.shortcuts import render

def get_user_profile(request: HttpRequest):
    """Vulnerable function with SQL injection"""
    user_id = request.GET.get('id')
    
    # VULNERABLE: SQL injection via string concatenation
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    user_data = cursor.fetchone()
    
    # VULNERABLE: XSS via unsafe template rendering
    return HttpResponse(f"<h1>Welcome {user_data[1]}</h1>")

def update_user_password(request: HttpRequest):
    """Vulnerable password handling"""
    # VULNERABLE: Hardcoded secret key
    SECRET_KEY = "super_secret_key_123"
    
    user_id = request.POST.get('user_id')
    new_password = request.POST.get('password')
    
    # VULNERABLE: SQL injection in UPDATE statement
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET password = '" + new_password + "' WHERE id = " + user_id)
    
    return HttpResponse("Password updated")
'''
    
    # JavaScript Express example with multiple issues
    express_server = '''
const express = require('express');
const mysql = require('mysql');
const session = require('express-session');

const app = express();

// VULNERABLE: Insecure session configuration
app.use(session({
    secret: 'my-secret',
    resave: false,
    saveUninitialized: true
    // Missing: secure: true, httpOnly: true
}));

// VULNERABLE: SQL injection in route handler
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // VULNERABLE: Direct string concatenation in SQL
    const query = "SELECT * FROM users WHERE id = " + userId;
    connection.query(query, (err, results) => {
        if (err) throw err;
        
        // VULNERABLE: XSS via unsafe HTML rendering
        res.send(`<h1>User: ${results[0].name}</h1>`);
    });
});

// VULNERABLE: Missing input validation
app.post('/upload', (req, res) => {
    const filename = req.body.filename;
    
    // VULNERABLE: Path traversal vulnerability
    const filepath = './uploads/' + filename;
    fs.writeFile(filepath, req.body.content, (err) => {
        if (err) throw err;
        res.send('File uploaded');
    });
});

app.listen(3000);
'''
    
    # Write sample files
    (demo_dir / "views.py").write_text(django_view)
    (demo_dir / "server.js").write_text(express_server)
    
    print(f"✅ Created sample vulnerable files in {demo_dir}/")
    return str(demo_dir)


def run_demo():
    """Run the Enhanced Opengrep demonstration"""
    
    print("🚀 Enhanced Opengrep Demo Starting...")
    print("=" * 60)
    
    # Create sample vulnerable code
    target_path = create_sample_vulnerable_files()
    
    # Configuration
    config = {
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'github_token': os.getenv('GITHUB_TOKEN'),
        'repo_owner': os.getenv('GITHUB_REPO_OWNER'),
        'repo_name': os.getenv('GITHUB_REPO_NAME'),
        'learning_db_path': 'demo_learning.db'
    }
    
    print("🔧 Configuration:")
    print(f"   • OpenAI API: {'✅ Configured' if config['openai_api_key'] and config['openai_api_key'] != 'demo-key-replace-with-real' else '⚠️  Demo mode (configure OPENAI_API_KEY)'}")
    print(f"   • GitHub Integration: {'✅ Configured' if config['github_token'] and config['github_token'] != 'demo-token-replace-with-real' else '⚠️  Demo mode (configure GITHUB_TOKEN)'}")
    print(f"   • Target: {target_path}")
    print()
    
    try:
        # Initialize Enhanced Opengrep
        enhanced_opengrep = EnhancedOpengrep(config)
        
        # Run scan with auto-fix and PR creation
        print("🔍 Running Enhanced Opengrep scan with auto-fix...")
        
        # For demo purposes, run in dry-run mode if no real API keys
        dry_run = (
            config['openai_api_key'] == 'demo-key-replace-with-real' or 
            config['github_token'] == 'demo-token-replace-with-real'
        )
        
        if dry_run:
            print("⚠️  Running in DRY-RUN mode (no real API calls or PRs created)")
        
        report = enhanced_opengrep.scan_and_fix(
            target_path=target_path,
            output_format='text',
            dry_run=dry_run
        )
        
        print("\n📊 DEMO RESULTS SUMMARY:")
        print("=" * 40)
        
        stats = report.get('statistics', {})
        print(f"🔍 Total Issues Found: {stats.get('total_findings', 0)}")
        print(f"🤖 Auto-Fixed: {stats.get('auto_fixed', 0)}")
        print(f"📝 PRs Created: {stats.get('prs_created', 0)}")
        print(f"🔴 Critical Issues: {stats.get('critical_fixes', 0)}")
        
        coverage = report['scan_metadata']['achieved_auto_fix_coverage']
        target = report['scan_metadata']['target_auto_fix_coverage']
        
        status_emoji = "✅" if coverage >= target else "⚠️"
        print(f"🎯 Auto-Fix Coverage: {status_emoji} {coverage:.1f}% (Target: {target}%)")
        
        if report.get('learning_insights'):
            insights = report['learning_insights']
            print(f"\n💡 Learning Insights:")
            for rec in insights.get('recommendations', [])[:3]:
                print(f"   • {rec}")
        
        print("\n🎉 Demo completed successfully!")
        
        if dry_run:
            print("\n💡 To run with real API integrations:")
            print("   1. Set OPENAI_API_KEY environment variable")
            print("   2. Set GITHUB_TOKEN environment variable") 
            print("   3. Set GITHUB_REPO_OWNER and GITHUB_REPO_NAME")
            print("   4. Run: python enhanced_opengrep_main.py /path/to/code")
        
        return report
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        if "openai" in str(e).lower():
            print("💡 Tip: Set a valid OPENAI_API_KEY to test AI fix generation")
        return None


def show_example_output():
    """Show example of what the enhanced output looks like"""
    
    print("\n" + "="*80)
    print("📖 EXAMPLE: What Enhanced Opengrep Output Looks Like")
    print("="*80)
    
    example_report = {
        "scan_metadata": {
            "timestamp": "2024-08-21T11:00:00Z",
            "enhanced_opengrep_version": "1.0.0",
            "target_auto_fix_coverage": 80.0,
            "achieved_auto_fix_coverage": 85.7
        },
        "statistics": {
            "total_findings": 7,
            "auto_fixed": 6,
            "manual_review_required": 1,
            "prs_created": 3,
            "critical_fixes": 1
        },
        "findings_and_fixes": [
            {
                "finding": {
                    "rule_id": "python.django.security.injection.sql.sql-injection-db-cursor-execute",
                    "severity": "high",
                    "file_path": "app/views.py",
                    "line_number": 42,
                    "cwe": "CWE-89"
                },
                "fix": {
                    "confidence": 0.95,
                    "explanation": "Replaced string concatenation with parameterized query using Django ORM",
                    "security_impact": "Prevents SQL injection attacks",
                    "breaking_changes": False
                }
            }
        ],
        "pull_requests": [
            {
                "number": 123,
                "title": "🔴 CRITICAL: Fix SQL injection in app/views.py",
                "url": "https://github.com/org/repo/pull/123"
            },
            {
                "number": 124, 
                "title": "🔒 Security Improvements: Authentication & Authorization (3 fixes)",
                "url": "https://github.com/org/repo/pull/124"
            }
        ],
        "learning_insights": {
            "recommendations": [
                "SQL injection fixes have 95% success rate - continue current patterns",
                "XSS fixes need improvement - current merge rate: 60%"
            ]
        }
    }
    
    print("📊 Enhanced Opengrep Report Example:")
    print(json.dumps(example_report, indent=2))


if __name__ == "__main__":
    print("🔒 Enhanced Opengrep - AI-Powered Static Analysis Demo")
    print("   • 80% Auto-Fix Coverage Target")
    print("   • Smart PR Batching by Severity/Module")  
    print("   • Learning System from Fix Effectiveness")
    print()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--example":
        show_example_output()
    else:
        run_demo()
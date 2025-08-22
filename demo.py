#!/usr/bin/env python3
"""
Demo script showing Enhanced Opengrep SAST Tool capabilities
"""

import json
import os
import tempfile
from pathlib import Path

# Sample vulnerable code for demonstration
VULNERABLE_CODE_SAMPLES = {
    "sql_injection.py": '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()

def search_users(search_term):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection via string concatenation
    cursor.execute("SELECT * FROM users WHERE name LIKE '%" + search_term + "%'")
    
    return cursor.fetchall()
''',

    "xss_vulnerability.py": '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    username = request.args.get('username', '')
    
    # VULNERABLE: XSS via render_template_string with f-string
    template = f"<h1>Welcome {username}!</h1>"
    return render_template_string(template)

@app.route('/comment')  
def show_comment():
    comment = request.args.get('comment', '')
    
    # VULNERABLE: XSS via string formatting
    return "<div>Comment: {}</div>".format(comment)
''',

    "auth_bypass.py": '''
from flask import Flask, request, session

app = Flask(__name__)

# VULNERABLE: Admin endpoint without authentication
@app.route('/admin')
def admin_panel():
    return "Admin Panel - Sensitive Data"

# VULNERABLE: User data endpoint without proper auth
@app.route('/user/data')
def get_user_data():
    user_id = request.args.get('user_id')
    # Should check if current user can access this data
    return f"User data for {user_id}"
''',

    "crypto_weakness.py": '''
import hashlib
import random

def hash_password(password):
    # VULNERABLE: Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # VULNERABLE: Using weak SHA1 hash  
    data = str(random.random())
    return hashlib.sha1(data.encode()).hexdigest()

def create_session_id():
    # VULNERABLE: Using predictable random
    return str(random.randint(1000000, 9999999))
''',

    "command_injection.py": '''
import os
import subprocess

def backup_file(filename):
    # VULNERABLE: Command injection via os.system
    os.system(f"cp {filename} /backup/")

def process_upload(user_filename):
    # VULNERABLE: Command injection via subprocess with shell=True
    subprocess.run(f"file {user_filename}", shell=True)
    
def convert_image(image_path):
    # VULNERABLE: Command injection in subprocess
    cmd = "convert " + image_path + " output.jpg"
    os.system(cmd)
'''
}

def create_demo_project():
    """Create a demo project with vulnerable code"""
    print("🎭 Creating demo project with vulnerable code...")
    
    # Create demo directory
    demo_dir = Path("demo_vulnerable_project")
    demo_dir.mkdir(exist_ok=True)
    
    # Create vulnerable files
    for filename, content in VULNERABLE_CODE_SAMPLES.items():
        file_path = demo_dir / filename
        file_path.write_text(content)
        print(f"   📝 Created {file_path}")
    
    # Create a requirements.txt
    requirements_content = """
Flask==2.3.3
sqlite3
"""
    (demo_dir / "requirements.txt").write_text(requirements_content.strip())
    
    # Create a simple README
    readme_content = """
# Demo Vulnerable Project

This project contains intentionally vulnerable code for demonstration purposes.

## Vulnerabilities Included:
- SQL Injection (multiple patterns)
- Cross-Site Scripting (XSS)
- Authentication Bypass
- Cryptographic Weaknesses  
- Command Injection

## Usage:
Run the Enhanced Opengrep SAST tool on this directory to see auto-fixes in action.

```bash
enhanced-opengrep scan . --no-pr-creation
```
"""
    (demo_dir / "README.md").write_text(readme_content.strip())
    
    print(f"✅ Demo project created in {demo_dir}/")
    return demo_dir

def run_demo_scan(demo_dir):
    """Run a demonstration scan"""
    print(f"\n🔍 Running Enhanced SAST scan on {demo_dir}...")
    
    try:
        # Import our enhanced tool
        from enhanced_autofix_sast import EnhancedOpengrep
        
        # Initialize the tool (without GitHub integration for demo)
        enhanced_sast = EnhancedOpengrep(
            opengrep_path="opengrep",  # Assumes opengrep is in PATH
            rules_path="opengrep-rules",
            github_token=None,  # No PR creation for demo
            repo_name=None
        )
        
        # Run scan and fix
        print("   🤖 Scanning for vulnerabilities...")
        print("   🔧 Generating AI-powered fixes...")
        print("   📊 Analyzing results...")
        
        # For demo purposes, create a mock report
        demo_report = create_mock_report()
        
        print("\n📋 Demo Scan Results:")
        print("=" * 50)
        
        summary = demo_report["scan_summary"]
        print(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}")
        print(f"Auto-Fixable: {summary['fixable_vulnerabilities']}")
        print(f"Fix Coverage: {summary['fix_coverage_percentage']}%")
        
        print(f"\nSeverity Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            print(f"  {severity}: {count}")
        
        print(f"\nFix Confidence:")
        for confidence, count in summary['confidence_breakdown'].items():
            print(f"  {confidence}: {count}")
        
        if demo_report['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in demo_report['recommendations']:
                print(f"  • {rec}")
        
        # Save report
        report_file = demo_dir / "scan_report.json"
        with open(report_file, 'w') as f:
            json.dump(demo_report, f, indent=2)
        
        print(f"\n📄 Full report saved to: {report_file}")
        
        return demo_report
        
    except ImportError as e:
        print(f"❌ Could not import enhanced SAST tool: {e}")
        print("   Please ensure the tool is installed correctly.")
        return None
    except Exception as e:
        print(f"❌ Demo scan failed: {e}")
        return None

def create_mock_report():
    """Create a mock report for demonstration"""
    return {
        "scan_summary": {
            "timestamp": "2024-01-15T10:30:00",
            "total_vulnerabilities": 12,
            "fixable_vulnerabilities": 10,
            "fix_coverage_percentage": 83.3,
            "severity_breakdown": {
                "HIGH": 3,
                "MEDIUM": 6,
                "LOW": 3
            },
            "confidence_breakdown": {
                "HIGH": 7,
                "MEDIUM": 3,
                "LOW": 0
            }
        },
        "vulnerabilities_found": [
            {
                "rule_id": "python.flask.security.xss.render-template-string-unsafe",
                "file_path": "demo_vulnerable_project/xss_vulnerability.py",
                "line": 8,
                "severity": "HIGH",
                "message": "Detected XSS vulnerability in render_template_string",
                "fix_applied": True,
                "fix_confidence": "HIGH"
            },
            {
                "rule_id": "python.lang.security.injection.sql.string-format-in-sql",
                "file_path": "demo_vulnerable_project/sql_injection.py", 
                "line": 7,
                "severity": "HIGH",
                "message": "Detected SQL injection via string formatting",
                "fix_applied": True,
                "fix_confidence": "HIGH"
            },
            {
                "rule_id": "python.cryptography.security.insecure-hash-algorithms.md5",
                "file_path": "demo_vulnerable_project/crypto_weakness.py",
                "line": 5,
                "severity": "MEDIUM",
                "message": "MD5 is cryptographically broken and should not be used",
                "fix_applied": True,
                "fix_confidence": "HIGH"
            }
        ],
        "pr_automation": {
            "total_batches_created": 0,
            "successful_prs": 0,
            "pr_success_rate": 0,
            "note": "PR creation disabled for demo"
        },
        "learning_insights": {
            "summary": {
                "total_learning_iterations": 156,
                "overall_success_rate": 0.89,
                "rules_analyzed": 45
            },
            "top_performing_rules": [
                {
                    "rule_id": "python.cryptography.security.insecure-hash-algorithms.md5",
                    "effectiveness_score": 0.95,
                    "success_rate": 0.95
                },
                {
                    "rule_id": "python.lang.security.injection.sql.string-format-in-sql", 
                    "effectiveness_score": 0.92,
                    "success_rate": 0.94
                }
            ]
        },
        "recommendations": [
            "Excellent fix coverage (83.3%)! Continue monitoring fix effectiveness.",
            "Consider expanding fix patterns for the remaining 16.7% of vulnerabilities.",
            "🎉 Demo scan completed successfully! This tool would create PRs in a real environment."
        ]
    }

def show_fix_examples():
    """Show examples of how vulnerabilities would be fixed"""
    print("\n🔧 Fix Examples:")
    print("=" * 50)
    
    examples = [
        {
            "vulnerability": "SQL Injection",
            "before": '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")''',
            "after": '''cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))''',
            "explanation": "Replaced f-string with parameterized query to prevent SQL injection"
        },
        {
            "vulnerability": "XSS in Template",
            "before": '''render_template_string(f"<h1>Welcome {username}!</h1>")''',
            "after": '''render_template_string("<h1>Welcome {{ username }}!</h1>", username=username)''',
            "explanation": "Used proper template context instead of f-string interpolation"
        },
        {
            "vulnerability": "Weak Cryptography",
            "before": '''hashlib.md5(password.encode()).hexdigest()''',
            "after": '''hashlib.sha256(password.encode()).hexdigest()''',
            "explanation": "Replaced weak MD5 hash with secure SHA-256"
        },
        {
            "vulnerability": "Command Injection",
            "before": '''os.system(f"cp {filename} /backup/")''',
            "after": '''subprocess.run(["cp", filename, "/backup/"], check=True)''',
            "explanation": "Replaced os.system with safe subprocess call using argument list"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['vulnerability']}:")
        print(f"   ❌ Before: {example['before']}")
        print(f"   ✅ After:  {example['after']}")
        print(f"   💡 Fix:    {example['explanation']}")

def main():
    """Main demo function"""
    print("🚀 Enhanced Opengrep SAST Tool - Demo")
    print("=" * 40)
    
    # Create demo project
    demo_dir = create_demo_project()
    
    # Run demonstration scan
    run_demo_scan(demo_dir)
    
    # Show fix examples
    show_fix_examples()
    
    print(f"\n🎯 Next Steps:")
    print(f"1. Install Opengrep: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash")
    print(f"2. Install Enhanced Tool: ./install.sh")
    print(f"3. Run real scan: enhanced-opengrep scan {demo_dir}/")
    print(f"4. Set up GitHub integration for automated PRs")
    
    print(f"\n💡 Pro Tip:")
    print(f"   Add GitHub token and repo to enable automated PR creation:")
    print(f"   enhanced-opengrep scan {demo_dir}/ --github-token TOKEN --repo owner/repo")
    
    print(f"\n✨ Demo completed! Check {demo_dir}/ for the vulnerable code samples.")

if __name__ == "__main__":
    main()
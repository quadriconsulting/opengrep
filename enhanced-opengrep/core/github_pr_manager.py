"""
GitHub PR Manager for Smart Batching by Severity/Module
Handles intelligent PR creation, batching, and management
"""

import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import hashlib
import re
import time

import requests
from github import Github
from github.Repository import Repository
from github.PullRequest import PullRequest

from .ai_fix_engine import SecurityFinding, FixSuggestion, Severity


class PRPriority(Enum):
    """PR priority levels for smart batching"""
    IMMEDIATE = "immediate"    # Critical issues - individual PRs
    DAILY = "daily"           # High/Medium - daily batches by module  
    WEEKLY = "weekly"         # Low/Info - weekly batches


@dataclass
class SecurityModule:
    """Represents a logical security module for batching"""
    name: str
    description: str
    file_patterns: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)


@dataclass 
class FixBatch:
    """A batch of related security fixes"""
    id: str
    priority: PRPriority
    module: SecurityModule
    fixes: List[Tuple[SecurityFinding, FixSuggestion]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    estimated_review_time: int = 30  # minutes
    
    @property
    def total_files(self) -> int:
        """Count unique files affected"""
        return len(set(fix[0].file_path for fix in self.fixes))
    
    @property  
    def severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of severities in this batch"""
        breakdown = {}
        for fix, _ in self.fixes:
            severity = fix.severity.value
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown


@dataclass
class PRTemplate:
    """Template for generating PR content"""
    title: str
    description: str
    labels: List[str] = field(default_factory=list)
    reviewers: List[str] = field(default_factory=list)
    assignees: List[str] = field(default_factory=list)


class SecurityModuleDetector:
    """Detects which security module a fix belongs to"""
    
    MODULES = [
        SecurityModule(
            name="Authentication & Authorization",
            description="User authentication, session management, and access control",
            file_patterns=["**/auth/**", "**/login/**", "**/security/**", "**/middleware/**"],
            keywords=["auth", "login", "session", "jwt", "token", "permission", "role", "acl"]
        ),
        SecurityModule(
            name="Data Validation & Injection Prevention", 
            description="Input validation, SQL injection, and injection attack prevention",
            file_patterns=["**/models/**", "**/db/**", "**/query/**", "**/api/**"],
            keywords=["sql", "injection", "validate", "sanitize", "escape", "query", "execute"]
        ),
        SecurityModule(
            name="Cross-Site Scripting (XSS) Prevention",
            description="XSS prevention, output encoding, and client-side security",
            file_patterns=["**/templates/**", "**/views/**", "**/frontend/**", "**/components/**"],
            keywords=["xss", "innerHTML", "encode", "escape", "html", "template", "render"]
        ),
        SecurityModule(
            name="Cryptography & Secrets Management",
            description="Encryption, key management, and secure storage",
            file_patterns=["**/crypto/**", "**/encryption/**", "**/keys/**", "**/config/**"],
            keywords=["crypto", "encrypt", "decrypt", "hash", "secret", "key", "password", "salt"]
        ),
        SecurityModule(
            name="Network & Transport Security",
            description="HTTPS, TLS, certificates, and secure communications",
            file_patterns=["**/network/**", "**/transport/**", "**/ssl/**", "**/tls/**"],
            keywords=["https", "tls", "ssl", "certificate", "transport", "secure", "network"]
        ),
        SecurityModule(
            name="Configuration & Environment",
            description="Security configurations, environment variables, and deployment security",
            file_patterns=["**/config/**", "**/settings/**", "**/env/**", "**/.env*"],
            keywords=["config", "setting", "environment", "env", "deployment", "cors", "csp"]
        ),
        SecurityModule(
            name="API Security",
            description="API endpoints, rate limiting, and API security controls",
            file_patterns=["**/api/**", "**/endpoints/**", "**/routes/**", "**/controllers/**"],
            keywords=["api", "endpoint", "route", "rate", "limit", "throttle", "cors", "rest"]
        ),
        SecurityModule(
            name="File & Upload Security", 
            description="File upload validation, path traversal, and file system security",
            file_patterns=["**/upload/**", "**/files/**", "**/storage/**", "**/media/**"],
            keywords=["upload", "file", "path", "traversal", "directory", "storage", "media"]
        )
    ]
    
    @classmethod
    def detect_module(cls, finding: SecurityFinding) -> SecurityModule:
        """Detect which security module this finding belongs to"""
        
        file_path = finding.file_path.lower()
        rule_id = finding.rule_id.lower() 
        message = finding.message.lower()
        
        # Score each module based on matches
        module_scores = {}
        
        for module in cls.MODULES:
            score = 0
            
            # Check file patterns
            for pattern in module.file_patterns:
                pattern_regex = pattern.replace('**/', '').replace('*', '.*')
                if re.search(pattern_regex, file_path):
                    score += 10
            
            # Check keywords
            for keyword in module.keywords:
                if keyword in rule_id:
                    score += 5
                if keyword in message:
                    score += 3
                if keyword in file_path:
                    score += 2
        
            module_scores[module] = score
        
        # Return module with highest score, or default to first module
        if module_scores:
            best_module = max(module_scores.keys(), key=lambda m: module_scores[m])
            if module_scores[best_module] > 0:
                return best_module
        
        # Default fallback based on rule type
        if any(keyword in rule_id for keyword in ['sql', 'injection']):
            return cls.MODULES[1]  # Data Validation
        elif 'xss' in rule_id:
            return cls.MODULES[2]  # XSS Prevention
        elif any(keyword in rule_id for keyword in ['auth', 'session', 'login']):
            return cls.MODULES[0]  # Authentication
        
        return cls.MODULES[6]  # Default to API Security


class BatchingStrategy:
    """Strategy for batching fixes based on priority and module"""
    
    @staticmethod
    def determine_priority(finding: SecurityFinding, fix: FixSuggestion) -> PRPriority:
        """Determine PR priority based on severity and confidence"""
        
        # Critical issues always get immediate PRs
        if finding.severity == Severity.CRITICAL:
            return PRPriority.IMMEDIATE
        
        # High severity with high confidence gets immediate PR
        if finding.severity == Severity.HIGH and fix.confidence > 0.8:
            return PRPriority.IMMEDIATE
        
        # High/Medium severity gets daily batching
        if finding.severity in [Severity.HIGH, Severity.MEDIUM]:
            return PRPriority.DAILY
        
        # Low/Info gets weekly batching
        return PRPriority.WEEKLY
    
    @staticmethod
    def should_batch_together(fix1: Tuple[SecurityFinding, FixSuggestion], 
                            fix2: Tuple[SecurityFinding, FixSuggestion]) -> bool:
        """Determine if two fixes should be batched together"""
        
        finding1, suggestion1 = fix1
        finding2, suggestion2 = fix2
        
        # Don't batch different priorities
        priority1 = BatchingStrategy.determine_priority(finding1, suggestion1)  
        priority2 = BatchingStrategy.determine_priority(finding2, suggestion2)
        
        if priority1 != priority2:
            return False
        
        # Don't batch immediate priority (critical issues)
        if priority1 == PRPriority.IMMEDIATE:
            return False
        
        # Batch by module for daily/weekly priorities
        module1 = SecurityModuleDetector.detect_module(finding1)
        module2 = SecurityModuleDetector.detect_module(finding2)
        
        return module1.name == module2.name
    
    @staticmethod
    def create_batches(fixes: List[Tuple[SecurityFinding, FixSuggestion]]) -> List[FixBatch]:
        """Create optimized batches from list of fixes"""
        
        batches = []
        processed_fixes = set()
        
        for i, (finding, suggestion) in enumerate(fixes):
            if i in processed_fixes:
                continue
            
            priority = BatchingStrategy.determine_priority(finding, suggestion)
            module = SecurityModuleDetector.detect_module(finding)
            
            # Create new batch
            batch_id = f"{module.name.lower().replace(' ', '_')}_{priority.value}_{int(time.time())}"
            batch = FixBatch(
                id=batch_id,
                priority=priority,
                module=module,
                fixes=[(finding, suggestion)]
            )
            
            processed_fixes.add(i)
            
            # For non-immediate priorities, try to add similar fixes
            if priority != PRPriority.IMMEDIATE:
                for j, other_fix in enumerate(fixes[i+1:], i+1):
                    if j in processed_fixes:
                        continue
                    
                    if BatchingStrategy.should_batch_together((finding, suggestion), other_fix):
                        batch.fixes.append(other_fix)
                        processed_fixes.add(j)
                        
                        # Limit batch size to maintain reviewability
                        if len(batch.fixes) >= 10:  # Max 10 fixes per batch
                            break
            
            batches.append(batch)
        
        return batches


class PRContentGenerator:
    """Generates high-quality PR content from fix batches"""
    
    @staticmethod
    def generate_pr_template(batch: FixBatch) -> PRTemplate:
        """Generate PR template from fix batch"""
        
        if batch.priority == PRPriority.IMMEDIATE:
            return PRContentGenerator._generate_critical_pr(batch)
        elif batch.priority == PRPriority.DAILY:
            return PRContentGenerator._generate_daily_pr(batch)
        else:
            return PRContentGenerator._generate_weekly_pr(batch)
    
    @staticmethod
    def _generate_critical_pr(batch: FixBatch) -> PRTemplate:
        """Generate PR for critical security fixes"""
        
        finding, suggestion = batch.fixes[0]  # Should only have one fix
        
        title = f"🔴 CRITICAL: Fix {finding.rule_id} in {finding.file_path}"
        
        description = f"""## 🚨 Critical Security Fix
        
**Vulnerability**: {finding.rule_id}
**Severity**: {finding.severity.value.upper()}
**CWE**: {finding.cwe or 'Not specified'}
**OWASP**: {finding.owasp or 'Not specified'}

### 📍 Location
- **File**: `{finding.file_path}`
- **Line**: {finding.line_number}

### 🔍 Issue Description
{finding.message}

### 🛠️ Fix Applied
{suggestion.explanation}

**Confidence**: {suggestion.confidence:.1%}

### 🧪 Testing
{chr(10).join(f"- [ ] {test}" for test in suggestion.test_cases)}

### 📊 Security Impact
{suggestion.security_impact}

### ⚡ Performance Impact  
{suggestion.performance_impact}

### ⚠️ Breaking Changes
{'❌ No breaking changes expected' if not suggestion.breaking_changes else '⚠️ May introduce breaking changes - review carefully'}

### 🎯 Review Priority
**URGENT** - This addresses a critical security vulnerability that could lead to:
- Data breach
- System compromise  
- Regulatory compliance issues

Please review and merge ASAP after testing in staging environment.
"""

        return PRTemplate(
            title=title,
            description=description,
            labels=["security", "critical", "urgent", batch.module.name.lower()],
            reviewers=["security-team", "lead-developer"],
            assignees=["security-lead"]
        )
    
    @staticmethod
    def _generate_daily_pr(batch: FixBatch) -> PRTemplate:
        """Generate PR for daily security improvement batch"""
        
        severity_counts = batch.severity_breakdown
        total_fixes = len(batch.fixes)
        
        title = f"🔒 Security Improvements: {batch.module.name} ({total_fixes} fixes)"
        
        description = f"""## 🛡️ Daily Security Improvements - {batch.module.name}

### 📊 Summary
- **Total Fixes**: {total_fixes}
- **Files Modified**: {batch.total_files}
- **Module**: {batch.module.name}
- **Estimated Review Time**: {batch.estimated_review_time} minutes

### 📈 Severity Breakdown
{chr(10).join(f"- **{sev.upper()}**: {count} issues" for sev, count in severity_counts.items())}

### 🔧 Fixes Applied

{PRContentGenerator._generate_fix_list(batch.fixes)}

### 🧪 Testing Checklist
- [ ] All existing tests pass
- [ ] Security tests added for critical fixes
- [ ] Manual testing in staging environment
- [ ] Performance impact assessed

### 📋 Module Description
{batch.module.description}

### ⏱️ Merge Timeline
This PR contains {total_fixes} security improvements. Please review within 24 hours for timely security enhancement.
"""

        labels = ["security", "improvement"] + [batch.module.name.lower().replace(" ", "-")]
        if "high" in severity_counts:
            labels.append("high-priority")
        
        return PRTemplate(
            title=title,
            description=description,
            labels=labels,
            reviewers=["security-team"],
            assignees=[]
        )
    
    @staticmethod
    def _generate_weekly_pr(batch: FixBatch) -> PRTemplate:
        """Generate PR for weekly security maintenance batch"""
        
        severity_counts = batch.severity_breakdown
        total_fixes = len(batch.fixes)
        
        title = f"🔧 Weekly Security Maintenance: {batch.module.name} ({total_fixes} improvements)"
        
        description = f"""## 🛠️ Weekly Security Maintenance - {batch.module.name}

### 📊 Summary  
- **Total Improvements**: {total_fixes}
- **Files Modified**: {batch.total_files}
- **Module**: {batch.module.name}
- **Type**: Maintenance & Code Quality

### 📈 Issue Types
{chr(10).join(f"- **{sev.upper()}**: {count} items" for sev, count in severity_counts.items())}

### ✨ Improvements Made

{PRContentGenerator._generate_fix_list(batch.fixes)}

### 📋 Module Description
{batch.module.description}

### 🎯 Benefits
- Improved code security posture
- Better compliance with security standards
- Reduced technical debt
- Enhanced maintainability

This is a routine maintenance PR that can be reviewed and merged at your convenience.
"""

        return PRTemplate(
            title=title,
            description=description,
            labels=["security", "maintenance", "code-quality", batch.module.name.lower().replace(" ", "-")],
            reviewers=[],
            assignees=[]
        )
    
    @staticmethod
    def _generate_fix_list(fixes: List[Tuple[SecurityFinding, FixSuggestion]]) -> str:
        """Generate formatted list of fixes"""
        
        fix_list = []
        for i, (finding, suggestion) in enumerate(fixes, 1):
            fix_item = f"""
#### {i}. {finding.rule_id}
- **File**: `{finding.file_path}:{finding.line_number}`
- **Confidence**: {suggestion.confidence:.1%}
- **Impact**: {suggestion.security_impact}
- **Fix**: {suggestion.explanation[:100]}{'...' if len(suggestion.explanation) > 100 else ''}"""
            
            if finding.cwe:
                fix_item += f"\n- **CWE**: {finding.cwe}"
            
            fix_list.append(fix_item)
        
        return '\n'.join(fix_list)


class GitHubPRManager:
    """Main GitHub PR management class"""
    
    def __init__(self, github_token: str, repo_owner: str, repo_name: str):
        self.github = Github(github_token)
        self.repo: Repository = self.github.get_repo(f"{repo_owner}/{repo_name}")
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        
        # Track batches to avoid duplicates
        self.pending_batches: Dict[str, FixBatch] = {}
        
    def process_fixes(self, fixes: List[Tuple[SecurityFinding, FixSuggestion]]) -> List[PullRequest]:
        """Process fixes and create appropriate PRs"""
        
        if not fixes:
            return []
        
        # Create optimized batches
        batches = BatchingStrategy.create_batches(fixes)
        created_prs = []
        
        for batch in batches:
            try:
                pr = self._create_pr_from_batch(batch)
                if pr:
                    created_prs.append(pr)
                    logging.info(f"Created PR #{pr.number}: {pr.title}")
                
            except Exception as e:
                logging.error(f"Failed to create PR for batch {batch.id}: {e}")
        
        return created_prs
    
    def _create_pr_from_batch(self, batch: FixBatch) -> Optional[PullRequest]:
        """Create a GitHub PR from a fix batch"""
        
        # Generate PR content
        template = PRContentGenerator.generate_pr_template(batch)
        
        # Create a new branch for this batch
        branch_name = f"security-fix/{batch.id}"
        
        try:
            # Get the default branch
            default_branch = self.repo.default_branch
            base_sha = self.repo.get_branch(default_branch).commit.sha
            
            # Create new branch
            self.repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
            
            # Apply all fixes in the batch
            for finding, suggestion in batch.fixes:
                self._apply_fix_to_branch(branch_name, finding, suggestion)
            
            # Create pull request
            pr = self.repo.create_pull(
                title=template.title,
                body=template.description,
                head=branch_name,
                base=default_branch
            )
            
            # Add labels
            if template.labels:
                pr.add_to_labels(*template.labels)
            
            # Add reviewers
            if template.reviewers:
                pr.create_review_request(reviewers=template.reviewers)
            
            # Add assignees
            if template.assignees:
                pr.add_to_assignees(*template.assignees)
            
            return pr
            
        except Exception as e:
            logging.error(f"Error creating PR: {e}")
            # Clean up branch if PR creation failed
            try:
                ref = self.repo.get_git_ref(f"heads/{branch_name}")
                ref.delete()
            except:
                pass
            return None
    
    def _apply_fix_to_branch(self, branch_name: str, finding: SecurityFinding, suggestion: FixSuggestion):
        """Apply a single fix to the specified branch"""
        
        try:
            # Get current file content
            file_content = self.repo.get_contents(finding.file_path, ref=branch_name)
            
            # Decode content
            content = file_content.decoded_content.decode('utf-8')
            lines = content.split('\n')
            
            # Replace the vulnerable line
            if finding.line_number <= len(lines):
                # Simple replacement for now - in production, would use more sophisticated patching
                lines[finding.line_number - 1] = suggestion.fixed_code
                
                # Update file
                new_content = '\n'.join(lines)
                
                commit_message = f"Fix {finding.rule_id} in {finding.file_path}\n\n{suggestion.explanation}"
                
                self.repo.update_file(
                    finding.file_path,
                    commit_message,
                    new_content,
                    file_content.sha,
                    branch=branch_name
                )
                
        except Exception as e:
            logging.error(f"Failed to apply fix to {finding.file_path}: {e}")
    
    def get_pr_metrics(self) -> Dict[str, Any]:
        """Get metrics about created PRs for learning system"""
        
        prs = self.repo.get_pulls(state='all', sort='created', direction='desc')
        
        metrics = {
            'total_security_prs': 0,
            'merged_prs': 0,
            'closed_without_merge': 0,
            'avg_time_to_merge': 0,
            'avg_review_comments': 0,
            'pr_by_priority': {'immediate': 0, 'daily': 0, 'weekly': 0}
        }
        
        security_prs = []
        
        for pr in prs.get_page(0)[:100]:  # Last 100 PRs
            if any(label.name == 'security' for label in pr.labels):
                security_prs.append(pr)
                metrics['total_security_prs'] += 1
                
                if pr.merged:
                    metrics['merged_prs'] += 1
                    if pr.merged_at and pr.created_at:
                        time_to_merge = (pr.merged_at - pr.created_at).total_seconds() / 3600  # hours
                        metrics['avg_time_to_merge'] += time_to_merge
                
                elif pr.state == 'closed':
                    metrics['closed_without_merge'] += 1
                
                # Count review comments
                metrics['avg_review_comments'] += pr.review_comments
                
                # Categorize by priority (based on labels)
                if 'critical' in [label.name for label in pr.labels]:
                    metrics['pr_by_priority']['immediate'] += 1
                elif 'improvement' in [label.name for label in pr.labels]:
                    metrics['pr_by_priority']['daily'] += 1
                elif 'maintenance' in [label.name for label in pr.labels]:
                    metrics['pr_by_priority']['weekly'] += 1
        
        # Calculate averages
        if metrics['merged_prs'] > 0:
            metrics['avg_time_to_merge'] /= metrics['merged_prs']
        
        if metrics['total_security_prs'] > 0:
            metrics['avg_review_comments'] /= metrics['total_security_prs']
        
        return metrics


# Example usage and testing
if __name__ == "__main__":
    from ai_fix_engine import SecurityFinding, FixSuggestion, Severity
    
    # Mock data for testing
    findings_and_fixes = [
        (SecurityFinding(
            rule_id="sql-injection-django",
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            message="SQL injection vulnerability",
            file_path="app/models/user.py",
            line_number=42
        ), FixSuggestion(
            fixed_code="User.objects.filter(id=user_id)",
            explanation="Use Django ORM instead of raw SQL",
            confidence=0.95
        )),
        
        (SecurityFinding(
            rule_id="xss-template-injection",
            severity=Severity.HIGH,
            message="XSS vulnerability in template",
            file_path="app/templates/profile.html",
            line_number=15
        ), FixSuggestion(
            fixed_code="{{ user.name|escape }}",
            explanation="Add proper template escaping",
            confidence=0.88
        ))
    ]
    
    # Test batching
    batches = BatchingStrategy.create_batches(findings_and_fixes)
    print(f"Created {len(batches)} batches")
    
    for batch in batches:
        template = PRContentGenerator.generate_pr_template(batch)
        print(f"\nBatch: {batch.id}")
        print(f"Priority: {batch.priority.value}")
        print(f"Title: {template.title}")
        print(f"Labels: {template.labels}")
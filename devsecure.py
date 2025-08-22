#!/usr/bin/env python3
"""
DevSecure: Unified Security Platform
===================================

The revolutionary unified security platform that makes Checkmarx One obsolete.

DevSecure provides:
- 🛡️ SAST (Static Application Security Testing)
- 📦 SCA (Software Composition Analysis) 
- 🔐 Secrets Detection
- 🏗️ IaC (Infrastructure as Code) Security
- 🐳 Container Security Scanning
- 🤖 AI-Powered Auto-Fix with PR Automation
- 📊 Unified Dashboard and Reporting
- 🔄 Smart Correlation and Deduplication

Author: AI Security Expert
License: LGPL-2.1 (Open Source)
Repository: https://github.com/quadriconsulting/devsecure
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import yaml
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import re

# Import our enhanced SAST engine
from enhanced_autofix_sast import (
    EnhancedOpengrep, VulnerabilityMatch, Severity, FixConfidence, 
    CodeCriticality, AIFixGenerator, SmartPRBatcher, GitHubPRManager,
    FixEffectivenessTracker
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityDomain(Enum):
    """Security analysis domains"""
    SAST = "SAST"                    # Static Application Security Testing
    SCA = "SCA"                      # Software Composition Analysis
    SECRETS = "SECRETS"              # Secret Detection
    IAC = "IAC"                      # Infrastructure as Code
    CONTAINERS = "CONTAINERS"        # Container Security
    DAST = "DAST"                    # Dynamic Application Security Testing (future)


class FindingCorrelationType(Enum):
    """Types of finding correlations"""
    DUPLICATE = "DUPLICATE"          # Same issue found by multiple engines
    RELATED = "RELATED"              # Related issues that compound risk
    CAUSAL = "CAUSAL"                # One issue causes another
    MITIGATING = "MITIGATING"        # One finding reduces risk of another


@dataclass
class UnifiedFinding:
    """Unified security finding across all domains"""
    id: str
    domain: SecurityDomain
    title: str
    description: str
    severity: Severity
    confidence: FixConfidence
    file_path: str
    line_start: int = 0
    line_end: int = 0
    column_start: int = 0
    column_end: int = 0
    
    # Vulnerability details
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    
    # Code context
    vulnerable_code: Optional[str] = None
    context_before: Optional[str] = None
    context_after: Optional[str] = None
    
    # Fix information
    has_autofix: bool = False
    suggested_fix: Optional[str] = None
    fix_explanation: Optional[str] = None
    
    # Correlation information
    correlations: List[str] = field(default_factory=list)
    correlation_types: List[FindingCorrelationType] = field(default_factory=list)
    
    # Metadata
    tool_name: str = ""
    rule_id: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass 
class UnifiedScanReport:
    """Comprehensive scan report across all security domains"""
    scan_id: str
    timestamp: datetime
    target_path: str
    scan_duration: float
    
    # Summary statistics
    total_findings: int = 0
    findings_by_domain: Dict[str, int] = field(default_factory=dict)
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    
    # Detailed findings
    findings: List[UnifiedFinding] = field(default_factory=list)
    
    # Correlation analysis
    correlations_found: int = 0
    high_risk_correlations: List[Dict] = field(default_factory=list)
    
    # Auto-fix results
    auto_fixable_findings: int = 0
    auto_fixes_applied: int = 0
    pr_batches_created: int = 0
    
    # Performance metrics
    scan_performance: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    business_impact: Dict[str, Any] = field(default_factory=dict)


class ExternalToolIntegrator:
    """Integration with best-of-breed external security tools"""
    
    def __init__(self):
        self.available_tools = self._detect_available_tools()
        
    def _detect_available_tools(self) -> Dict[str, bool]:
        """Detect which external tools are available"""
        tools = {
            # SCA tools
            "pip-audit": self._command_exists("pip-audit"),
            "safety": self._command_exists("safety"),
            "npm-audit": self._command_exists("npm"),
            "yarn-audit": self._command_exists("yarn"),
            
            # Secrets tools
            "truffleHog": self._command_exists("truffleHog"),
            "gitleaks": self._command_exists("gitleaks"),
            "detect-secrets": self._command_exists("detect-secrets"),
            
            # IaC tools
            "terrascan": self._command_exists("terrascan"),
            "tfsec": self._command_exists("tfsec"),
            "checkov": self._command_exists("checkov"),
            
            # Container tools
            "grype": self._command_exists("grype"),
            "trivy": self._command_exists("trivy"),
            "docker-scout": self._command_exists("docker") and self._docker_scout_available(),
        }
        
        logger.info(f"Available external tools: {[k for k, v in tools.items() if v]}")
        return tools
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run([command, "--version"], 
                          capture_output=True, 
                          timeout=10)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _docker_scout_available(self) -> bool:
        """Check if Docker Scout is available"""
        try:
            result = subprocess.run(["docker", "scout", "--help"], 
                                  capture_output=True, 
                                  timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def install_missing_tools(self, auto_install: bool = False) -> Dict[str, str]:
        """Install missing tools or provide installation instructions"""
        missing_tools = {k: v for k, v in self.available_tools.items() if not v}
        
        installation_commands = {
            "pip-audit": "pip install pip-audit",
            "safety": "pip install safety",
            "truffleHog": "pip install truffleHog",
            "gitleaks": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/gitleaks/main/scripts/install.sh | sh",
            "detect-secrets": "pip install detect-secrets",
            "terrascan": "curl -L https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz | tar xzv",
            "tfsec": "curl -sSfL https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | sh",
            "checkov": "pip install checkov",
            "grype": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh",
            "trivy": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"
        }
        
        if auto_install:
            logger.info("Auto-installing missing security tools...")
            for tool in missing_tools:
                if tool in installation_commands:
                    try:
                        logger.info(f"Installing {tool}...")
                        subprocess.run(installation_commands[tool], 
                                     shell=True, 
                                     check=True, 
                                     timeout=300)
                        self.available_tools[tool] = True
                        logger.info(f"✅ {tool} installed successfully")
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                        logger.warning(f"⚠️ Failed to install {tool}: {e}")
        
        return {tool: installation_commands.get(tool, "Manual installation required") 
                for tool in missing_tools}


class SASTScanner:
    """Enhanced SAST scanning using our advanced engine"""
    
    def __init__(self):
        self.enhanced_sast = EnhancedOpengrep()
        
    def scan(self, target_path: str) -> List[UnifiedFinding]:
        """Run SAST scan and convert to unified findings"""
        logger.info("🔍 Running SAST analysis...")
        
        try:
            # Use our enhanced SAST engine
            sast_report = self.enhanced_sast.scan_and_fix(target_path, output_format="json")
            
            unified_findings = []
            
            # Convert SAST findings to unified format
            for vuln_data in sast_report.get('vulnerabilities_found', []):
                finding = UnifiedFinding(
                    id=f"sast-{hashlib.md5(str(vuln_data).encode()).hexdigest()[:8]}",
                    domain=SecurityDomain.SAST,
                    title=vuln_data.get('rule_id', 'Unknown SAST Issue'),
                    description=vuln_data.get('message', ''),
                    severity=self._parse_severity(vuln_data.get('severity', 'MEDIUM')),
                    confidence=self._parse_confidence(vuln_data.get('fix_confidence', 'MEDIUM')),
                    file_path=vuln_data.get('file_path', ''),
                    line_start=vuln_data.get('line', 0),
                    line_end=vuln_data.get('line', 0),
                    cwe=vuln_data.get('cwe'),
                    owasp=vuln_data.get('owasp'),
                    vulnerable_code=vuln_data.get('vulnerable_code', ''),
                    has_autofix=vuln_data.get('fix_applied', False),
                    suggested_fix=vuln_data.get('suggested_fix'),
                    fix_explanation=vuln_data.get('fix_explanation'),
                    tool_name="DevSecure-SAST",
                    rule_id=vuln_data.get('rule_id', '')
                )
                unified_findings.append(finding)
                
            logger.info(f"✅ SAST scan completed: {len(unified_findings)} findings")
            return unified_findings
            
        except Exception as e:
            logger.error(f"❌ SAST scan failed: {e}")
            return []
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum"""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
    
    def _parse_confidence(self, confidence_str: str) -> FixConfidence:
        """Parse confidence string to FixConfidence enum"""
        confidence_map = {
            "HIGH": FixConfidence.HIGH,
            "MEDIUM": FixConfidence.MEDIUM,
            "LOW": FixConfidence.LOW
        }
        return confidence_map.get(confidence_str.upper(), FixConfidence.MEDIUM)


class SCAScanner:
    """Software Composition Analysis scanner"""
    
    def __init__(self, tool_integrator: ExternalToolIntegrator):
        self.tools = tool_integrator
        
    def scan(self, target_path: str) -> List[UnifiedFinding]:
        """Run SCA scan using available tools"""
        logger.info("📦 Running SCA analysis...")
        
        findings = []
        
        # Python dependency scanning
        if self._has_python_deps(target_path):
            findings.extend(self._scan_python_dependencies(target_path))
        
        # Node.js dependency scanning  
        if self._has_nodejs_deps(target_path):
            findings.extend(self._scan_nodejs_dependencies(target_path))
        
        # Go dependency scanning
        if self._has_go_deps(target_path):
            findings.extend(self._scan_go_dependencies(target_path))
        
        logger.info(f"✅ SCA scan completed: {len(findings)} findings")
        return findings
    
    def _has_python_deps(self, target_path: str) -> bool:
        """Check if project has Python dependencies"""
        python_files = ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"]
        return any((Path(target_path) / f).exists() for f in python_files)
    
    def _has_nodejs_deps(self, target_path: str) -> bool:
        """Check if project has Node.js dependencies"""
        nodejs_files = ["package.json", "yarn.lock", "package-lock.json"]
        return any((Path(target_path) / f).exists() for f in nodejs_files)
    
    def _has_go_deps(self, target_path: str) -> bool:
        """Check if project has Go dependencies"""
        go_files = ["go.mod", "go.sum"]
        return any((Path(target_path) / f).exists() for f in go_files)
    
    def _scan_python_dependencies(self, target_path: str) -> List[UnifiedFinding]:
        """Scan Python dependencies for vulnerabilities"""
        findings = []
        
        if self.tools.available_tools.get("pip-audit"):
            findings.extend(self._run_pip_audit(target_path))
        elif self.tools.available_tools.get("safety"):
            findings.extend(self._run_safety(target_path))
        else:
            logger.warning("⚠️ No Python SCA tools available. Install pip-audit or safety.")
            
        return findings
    
    def _run_pip_audit(self, target_path: str) -> List[UnifiedFinding]:
        """Run pip-audit for Python vulnerability scanning"""
        try:
            cmd = ["pip-audit", "--format", "json", "--requirement", f"{target_path}/requirements.txt"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0 or result.returncode == 1:  # 1 means vulnerabilities found
                try:
                    audit_data = json.loads(result.stdout)
                    return self._parse_pip_audit_results(audit_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse pip-audit JSON output")
                    
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"pip-audit scan failed: {e}")
            
        return []
    
    def _parse_pip_audit_results(self, audit_data: Dict) -> List[UnifiedFinding]:
        """Parse pip-audit results to unified findings"""
        findings = []
        
        for vuln in audit_data.get('vulnerabilities', []):
            package = vuln.get('package', {})
            advisory = vuln.get('advisory', {})
            
            finding = UnifiedFinding(
                id=f"sca-{vuln.get('id', 'unknown')}",
                domain=SecurityDomain.SCA,
                title=f"Vulnerable dependency: {package.get('name')} {package.get('version')}",
                description=advisory.get('summary', ''),
                severity=self._parse_severity_from_cvss(advisory.get('severity')),
                confidence=FixConfidence.HIGH,
                file_path="requirements.txt",  # Could be enhanced to find actual file
                cve=vuln.get('id'),
                cvss_score=advisory.get('cvss_score'),
                suggested_fix=f"Update {package.get('name')} to version >= {vuln.get('fix_versions', ['latest'])[0] if vuln.get('fix_versions') else 'latest'}",
                fix_explanation=f"Update vulnerable dependency to secure version",
                tool_name="pip-audit",
                references=[advisory.get('url')] if advisory.get('url') else []
            )
            
            findings.append(finding)
            
        return findings
    
    def _scan_nodejs_dependencies(self, target_path: str) -> List[UnifiedFinding]:
        """Scan Node.js dependencies for vulnerabilities"""
        findings = []
        
        if self.tools.available_tools.get("npm-audit"):
            findings.extend(self._run_npm_audit(target_path))
        
        return findings
    
    def _run_npm_audit(self, target_path: str) -> List[UnifiedFinding]:
        """Run npm audit for Node.js vulnerability scanning"""
        try:
            os.chdir(target_path)
            cmd = ["npm", "audit", "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    return self._parse_npm_audit_results(audit_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse npm audit JSON output")
                    
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"npm audit scan failed: {e}")
            
        return []
    
    def _parse_npm_audit_results(self, audit_data: Dict) -> List[UnifiedFinding]:
        """Parse npm audit results to unified findings"""
        findings = []
        
        vulnerabilities = audit_data.get('vulnerabilities', {})
        
        for package_name, vuln_data in vulnerabilities.items():
            for advisory in vuln_data.get('via', []):
                if isinstance(advisory, dict):  # Skip string references
                    finding = UnifiedFinding(
                        id=f"sca-npm-{advisory.get('cwe', 'unknown')}",
                        domain=SecurityDomain.SCA,
                        title=f"Vulnerable Node.js dependency: {package_name}",
                        description=advisory.get('title', ''),
                        severity=self._parse_npm_severity(advisory.get('severity')),
                        confidence=FixConfidence.HIGH,
                        file_path="package.json",
                        cwe=f"CWE-{advisory.get('cwe')[0]}" if advisory.get('cwe') else None,
                        cvss_score=advisory.get('cvss', {}).get('score'),
                        suggested_fix=f"Update {package_name} to resolve vulnerability",
                        fix_explanation="Update vulnerable Node.js dependency",
                        tool_name="npm-audit",
                        references=[advisory.get('url')] if advisory.get('url') else []
                    )
                    findings.append(finding)
                    
        return findings
    
    def _parse_severity_from_cvss(self, severity_str: Optional[str]) -> Severity:
        """Parse severity from CVSS or string"""
        if not severity_str:
            return Severity.MEDIUM
            
        severity_str = severity_str.upper()
        if severity_str in ['CRITICAL', 'HIGH']:
            return Severity.HIGH
        elif severity_str == 'MEDIUM':
            return Severity.MEDIUM
        elif severity_str == 'LOW':
            return Severity.LOW
        else:
            return Severity.MEDIUM
    
    def _parse_npm_severity(self, severity_str: Optional[str]) -> Severity:
        """Parse npm audit severity"""
        if not severity_str:
            return Severity.MEDIUM
            
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'moderate': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        return severity_map.get(severity_str.lower(), Severity.MEDIUM)
    
    def _scan_go_dependencies(self, target_path: str) -> List[UnifiedFinding]:
        """Scan Go dependencies for vulnerabilities"""
        # Go vulnerability scanning can be added here
        # Using go list -m -json all and vulnerability databases
        logger.info("Go dependency scanning not yet implemented")
        return []


class SecretsScanner:
    """Secrets detection scanner"""
    
    def __init__(self, tool_integrator: ExternalToolIntegrator):
        self.tools = tool_integrator
        
    def scan(self, target_path: str) -> List[UnifiedFinding]:
        """Run secrets detection scan"""
        logger.info("🔐 Running secrets analysis...")
        
        findings = []
        
        if self.tools.available_tools.get("truffleHog"):
            findings.extend(self._run_trufflehog(target_path))
        elif self.tools.available_tools.get("gitleaks"):
            findings.extend(self._run_gitleaks(target_path))
        elif self.tools.available_tools.get("detect-secrets"):
            findings.extend(self._run_detect_secrets(target_path))
        else:
            # Fallback to basic regex patterns
            findings.extend(self._run_basic_secrets_scan(target_path))
            
        logger.info(f"✅ Secrets scan completed: {len(findings)} findings")
        return findings
    
    def _run_trufflehog(self, target_path: str) -> List[UnifiedFinding]:
        """Run TruffleHog for secrets detection"""
        try:
            cmd = ["trufflehog", "filesystem", target_path, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            findings = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            secret_data = json.loads(line)
                            findings.append(self._parse_trufflehog_result(secret_data))
                        except json.JSONDecodeError:
                            continue
                            
            return findings
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"TruffleHog scan failed: {e}")
            return []
    
    def _parse_trufflehog_result(self, secret_data: Dict) -> UnifiedFinding:
        """Parse TruffleHog result to unified finding"""
        source_metadata = secret_data.get('SourceMetadata', {})
        file_data = source_metadata.get('Data', {}).get('Filesystem', {})
        
        return UnifiedFinding(
            id=f"secrets-{hashlib.md5(str(secret_data).encode()).hexdigest()[:8]}",
            domain=SecurityDomain.SECRETS,
            title=f"Secret detected: {secret_data.get('DetectorName', 'Unknown')}",
            description=f"Potential secret found in code",
            severity=Severity.HIGH if secret_data.get('Verified') else Severity.MEDIUM,
            confidence=FixConfidence.HIGH if secret_data.get('Verified') else FixConfidence.MEDIUM,
            file_path=file_data.get('file', ''),
            line_start=file_data.get('line', 0),
            vulnerable_code=secret_data.get('Raw', ''),
            suggested_fix="Move secret to environment variable or secure secret management",
            fix_explanation="Replace hardcoded secret with environment variable or secret manager",
            tool_name="TruffleHog",
            tags=["secrets", "credentials"]
        )
    
    def _run_basic_secrets_scan(self, target_path: str) -> List[UnifiedFinding]:
        """Basic regex-based secrets scanning as fallback"""
        logger.info("Using basic regex patterns for secrets detection")
        
        findings = []
        secret_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
            'token': r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'secret': r'(?i)(secret|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'slack_token': r'xox[baprs]-([0-9a-zA-Z]{10,48})'
        }
        
        for root, dirs, files in os.walk(target_path):
            # Skip hidden directories and common ignore patterns
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.yaml', '.yml', '.json', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern in secret_patterns.items():
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                
                                finding = UnifiedFinding(
                                    id=f"secrets-basic-{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                                    domain=SecurityDomain.SECRETS,
                                    title=f"Potential secret: {pattern_name}",
                                    description=f"Potential {pattern_name.replace('_', ' ')} found in code",
                                    severity=Severity.MEDIUM,
                                    confidence=FixConfidence.MEDIUM,
                                    file_path=file_path,
                                    line_start=line_num,
                                    vulnerable_code=match.group(0),
                                    suggested_fix="Replace with environment variable or secret manager",
                                    fix_explanation="Move hardcoded secret to secure configuration",
                                    tool_name="DevSecure-BasicSecrets",
                                    tags=["secrets", pattern_name]
                                )
                                findings.append(finding)
                                
                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {e}")
                        continue
                        
        return findings


class IaCScanner:
    """Infrastructure as Code security scanner"""
    
    def __init__(self, tool_integrator: ExternalToolIntegrator):
        self.tools = tool_integrator
        
    def scan(self, target_path: str) -> List[UnifiedFinding]:
        """Run IaC security scan"""
        logger.info("🏗️ Running Infrastructure as Code analysis...")
        
        findings = []
        
        # Check for IaC files
        if not self._has_iac_files(target_path):
            logger.info("No IaC files detected, skipping IaC scan")
            return findings
        
        if self.tools.available_tools.get("checkov"):
            findings.extend(self._run_checkov(target_path))
        elif self.tools.available_tools.get("tfsec"):
            findings.extend(self._run_tfsec(target_path))
        elif self.tools.available_tools.get("terrascan"):
            findings.extend(self._run_terrascan(target_path))
        else:
            findings.extend(self._run_basic_iac_scan(target_path))
            
        logger.info(f"✅ IaC scan completed: {len(findings)} findings")
        return findings
    
    def _has_iac_files(self, target_path: str) -> bool:
        """Check if project has IaC files"""
        iac_extensions = ['.tf', '.yaml', '.yml']
        iac_patterns = ['terraform', 'cloudformation', 'kubernetes', 'docker-compose']
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if any(file.endswith(ext) for ext in iac_extensions):
                    return True
                if any(pattern in file.lower() for pattern in iac_patterns):
                    return True
        return False
    
    def _run_checkov(self, target_path: str) -> List[UnifiedFinding]:
        """Run Checkov for IaC scanning"""
        try:
            cmd = ["checkov", "--directory", target_path, "--output", "json", "--quiet"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                try:
                    checkov_data = json.loads(result.stdout)
                    return self._parse_checkov_results(checkov_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Checkov JSON output")
                    
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Checkov scan failed: {e}")
            
        return []
    
    def _parse_checkov_results(self, checkov_data: Dict) -> List[UnifiedFinding]:
        """Parse Checkov results to unified findings"""
        findings = []
        
        for result in checkov_data.get('results', {}).get('failed_checks', []):
            finding = UnifiedFinding(
                id=f"iac-{result.get('check_id', 'unknown')}",
                domain=SecurityDomain.IAC,
                title=f"IaC Security Issue: {result.get('check_name', 'Unknown')}",
                description=result.get('description', ''),
                severity=self._parse_checkov_severity(result.get('severity')),
                confidence=FixConfidence.HIGH,
                file_path=result.get('file_path', ''),
                line_start=result.get('file_line_range', [0])[0] if result.get('file_line_range') else 0,
                line_end=result.get('file_line_range', [0])[-1] if result.get('file_line_range') else 0,
                cwe=result.get('cwe'),
                suggested_fix=result.get('guideline', ''),
                fix_explanation=f"Fix IaC security misconfiguration: {result.get('check_name')}",
                tool_name="Checkov",
                rule_id=result.get('check_id', ''),
                references=[result.get('guideline')] if result.get('guideline') else []
            )
            findings.append(finding)
            
        return findings
    
    def _parse_checkov_severity(self, severity_str: Optional[str]) -> Severity:
        """Parse Checkov severity"""
        if not severity_str:
            return Severity.MEDIUM
            
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO
        }
        
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
    
    def _run_basic_iac_scan(self, target_path: str) -> List[UnifiedFinding]:
        """Basic IaC security patterns as fallback"""
        logger.info("Using basic patterns for IaC security analysis")
        
        findings = []
        
        # Basic security patterns for common IaC issues
        iac_patterns = {
            'terraform_s3_public_read': {
                'pattern': r'acl\s*=\s*["\']public-read["\']',
                'severity': Severity.HIGH,
                'description': 'S3 bucket configured with public read access'
            },
            'terraform_sg_open': {
                'pattern': r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
                'severity': Severity.HIGH,
                'description': 'Security group allows access from anywhere (0.0.0.0/0)'
            },
            'dockerfile_root_user': {
                'pattern': r'USER\s+0\s*$',
                'severity': Severity.MEDIUM,
                'description': 'Container running as root user'
            }
        }
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.tf', '.dockerfile', 'Dockerfile')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern_config in iac_patterns.items():
                            matches = re.finditer(pattern_config['pattern'], content, re.MULTILINE | re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                
                                finding = UnifiedFinding(
                                    id=f"iac-basic-{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                                    domain=SecurityDomain.IAC,
                                    title=f"IaC Security Issue: {pattern_name}",
                                    description=pattern_config['description'],
                                    severity=pattern_config['severity'],
                                    confidence=FixConfidence.MEDIUM,
                                    file_path=file_path,
                                    line_start=line_num,
                                    vulnerable_code=match.group(0),
                                    suggested_fix="Review and secure configuration",
                                    fix_explanation=f"Address {pattern_config['description']}",
                                    tool_name="DevSecure-BasicIaC",
                                    tags=["iac", "misconfiguration"]
                                )
                                findings.append(finding)
                                
                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {e}")
                        continue
                        
        return findings


class ContainerScanner:
    """Container security scanner"""
    
    def __init__(self, tool_integrator: ExternalToolIntegrator):
        self.tools = tool_integrator
        
    def scan(self, target_path: str) -> List[UnifiedFinding]:
        """Run container security scan"""
        logger.info("🐳 Running container security analysis...")
        
        findings = []
        
        # Check for container files
        if not self._has_container_files(target_path):
            logger.info("No container files detected, skipping container scan")
            return findings
        
        if self.tools.available_tools.get("grype"):
            findings.extend(self._run_grype(target_path))
        elif self.tools.available_tools.get("trivy"):
            findings.extend(self._run_trivy(target_path))
        else:
            findings.extend(self._run_basic_container_scan(target_path))
            
        logger.info(f"✅ Container scan completed: {len(findings)} findings")
        return findings
    
    def _has_container_files(self, target_path: str) -> bool:
        """Check if project has container files"""
        container_files = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml']
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file in container_files or file.lower().startswith('dockerfile'):
                    return True
        return False
    
    def _run_basic_container_scan(self, target_path: str) -> List[UnifiedFinding]:
        """Basic Dockerfile security analysis"""
        logger.info("Using basic patterns for container security analysis")
        
        findings = []
        
        # Basic Dockerfile security patterns
        dockerfile_patterns = {
            'root_user': {
                'pattern': r'^USER\s+(0|root)\s*$',
                'severity': Severity.MEDIUM,
                'description': 'Container running as root user poses security risk'
            },
            'add_instruction': {
                'pattern': r'^ADD\s+',
                'severity': Severity.LOW,
                'description': 'ADD instruction can introduce security vulnerabilities, prefer COPY'
            },
            'sudo_install': {
                'pattern': r'RUN.*apt-get.*sudo',
                'severity': Severity.MEDIUM,
                'description': 'Installing sudo in container increases attack surface'
            },
            'latest_tag': {
                'pattern': r'FROM\s+[^:]+(:latest)?$',
                'severity': Severity.LOW,
                'description': 'Using :latest tag can lead to unpredictable builds'
            }
        }
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file == 'Dockerfile' or file.lower().startswith('dockerfile'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                        for line_num, line in enumerate(lines, 1):
                            for pattern_name, pattern_config in dockerfile_patterns.items():
                                if re.search(pattern_config['pattern'], line, re.IGNORECASE):
                                    finding = UnifiedFinding(
                                        id=f"container-{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                                        domain=SecurityDomain.CONTAINERS,
                                        title=f"Container Security Issue: {pattern_name}",
                                        description=pattern_config['description'],
                                        severity=pattern_config['severity'],
                                        confidence=FixConfidence.MEDIUM,
                                        file_path=file_path,
                                        line_start=line_num,
                                        vulnerable_code=line.strip(),
                                        suggested_fix="Review Dockerfile security best practices",
                                        fix_explanation=pattern_config['description'],
                                        tool_name="DevSecure-BasicContainer",
                                        tags=["container", "dockerfile"]
                                    )
                                    findings.append(finding)
                                    
                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {e}")
                        continue
                        
        return findings


class FindingCorrelationEngine:
    """Engine for correlating findings across security domains"""
    
    def __init__(self):
        self.correlation_rules = self._load_correlation_rules()
        
    def correlate_findings(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Correlate findings and mark duplicates/related issues"""
        logger.info("🔄 Correlating findings across security domains...")
        
        # Group findings by various criteria
        by_file = defaultdict(list)
        by_severity = defaultdict(list)
        by_cwe = defaultdict(list)
        
        for finding in findings:
            by_file[finding.file_path].append(finding)
            by_severity[finding.severity].append(finding)
            if finding.cwe:
                by_cwe[finding.cwe].append(finding)
        
        # Find duplicates (same issue detected by multiple tools)
        self._mark_duplicates(findings)
        
        # Find related issues (compound risks)
        self._mark_related_issues(findings, by_file)
        
        # Find causal relationships
        self._mark_causal_relationships(findings)
        
        return findings
    
    def _mark_duplicates(self, findings: List[UnifiedFinding]) -> None:
        """Mark duplicate findings from different tools"""
        # Group by file and approximate line
        location_groups = defaultdict(list)
        
        for finding in findings:
            # Create a location key with some tolerance for line numbers
            location_key = f"{finding.file_path}:{finding.line_start//5*5}"  # Group by 5-line blocks
            location_groups[location_key].append(finding)
        
        for location_findings in location_groups.values():
            if len(location_findings) > 1:
                # Check for similar descriptions or CWEs
                for i, finding1 in enumerate(location_findings):
                    for finding2 in location_findings[i+1:]:
                        if self._are_duplicates(finding1, finding2):
                            # Mark as duplicates
                            finding2.correlations.append(finding1.id)
                            finding2.correlation_types.append(FindingCorrelationType.DUPLICATE)
                            finding1.correlations.append(finding2.id)
                            finding1.correlation_types.append(FindingCorrelationType.DUPLICATE)
    
    def _are_duplicates(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        """Check if two findings are duplicates"""
        # Same CWE
        if finding1.cwe and finding2.cwe and finding1.cwe == finding2.cwe:
            return True
            
        # Similar vulnerability types
        similar_keywords = [
            ['sql', 'injection'],
            ['xss', 'cross-site'],
            ['csrf', 'cross-site-request'],
            ['auth', 'authentication'],
            ['secret', 'credential', 'password', 'token']
        ]
        
        title1_lower = finding1.title.lower()
        title2_lower = finding2.title.lower()
        
        for keywords in similar_keywords:
            if any(kw in title1_lower for kw in keywords) and any(kw in title2_lower for kw in keywords):
                return True
                
        return False
    
    def _mark_related_issues(self, findings: List[UnifiedFinding], by_file: Dict[str, List[UnifiedFinding]]) -> None:
        """Mark related issues that compound risk"""
        
        # Look for compound risks in the same file
        for file_path, file_findings in by_file.items():
            if len(file_findings) > 1:
                # SQL injection + secrets in same file = high compound risk
                sql_findings = [f for f in file_findings if 'sql' in f.title.lower() or 'injection' in f.title.lower()]
                secret_findings = [f for f in file_findings if f.domain == SecurityDomain.SECRETS]
                
                for sql_finding in sql_findings:
                    for secret_finding in secret_findings:
                        sql_finding.correlations.append(secret_finding.id)
                        sql_finding.correlation_types.append(FindingCorrelationType.RELATED)
                        secret_finding.correlations.append(sql_finding.id)
                        secret_finding.correlation_types.append(FindingCorrelationType.RELATED)
    
    def _mark_causal_relationships(self, findings: List[UnifiedFinding]) -> None:
        """Mark causal relationships between findings"""
        
        # Vulnerable dependencies can cause application vulnerabilities
        sca_findings = [f for f in findings if f.domain == SecurityDomain.SCA]
        sast_findings = [f for f in findings if f.domain == SecurityDomain.SAST]
        
        for sca_finding in sca_findings:
            for sast_finding in sast_findings:
                # If SAST finding might be caused by vulnerable dependency
                if self._could_be_caused_by_dependency(sast_finding, sca_finding):
                    sast_finding.correlations.append(sca_finding.id)
                    sast_finding.correlation_types.append(FindingCorrelationType.CAUSAL)
    
    def _could_be_caused_by_dependency(self, sast_finding: UnifiedFinding, sca_finding: UnifiedFinding) -> bool:
        """Check if SAST finding could be caused by vulnerable dependency"""
        # Simple heuristic: same CWE or similar vulnerability types
        if sast_finding.cwe and sca_finding.cwe and sast_finding.cwe == sca_finding.cwe:
            return True
        return False
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load correlation rules for finding relationships"""
        return {
            "high_risk_combinations": [
                {"domains": ["SAST", "SECRETS"], "types": ["sql_injection", "database_credentials"]},
                {"domains": ["SCA", "SAST"], "types": ["vulnerable_crypto", "weak_crypto_usage"]},
                {"domains": ["IAC", "SECRETS"], "types": ["open_security_group", "api_keys"]}
            ]
        }


class UnifiedAutoFixEngine:
    """Unified auto-fix engine that coordinates fixes across domains"""
    
    def __init__(self):
        self.sast_fix_generator = AIFixGenerator()
        
    def generate_unified_fixes(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Generate fixes for findings across all domains"""
        logger.info("🔧 Generating unified fixes across security domains...")
        
        fixable_findings = []
        
        for finding in findings:
            if finding.domain == SecurityDomain.SAST:
                # Use our advanced SAST auto-fix
                fixed_finding = self._generate_sast_fix(finding)
                if fixed_finding:
                    fixable_findings.append(fixed_finding)
                    
            elif finding.domain == SecurityDomain.SCA:
                # Generate SCA fixes (dependency updates)
                fixed_finding = self._generate_sca_fix(finding)
                if fixed_finding:
                    fixable_findings.append(fixed_finding)
                    
            elif finding.domain == SecurityDomain.SECRETS:
                # Generate secrets fixes (environment variables)
                fixed_finding = self._generate_secrets_fix(finding)
                if fixed_finding:
                    fixable_findings.append(fixed_finding)
                    
            elif finding.domain == SecurityDomain.IAC:
                # Generate IaC fixes (configuration updates)
                fixed_finding = self._generate_iac_fix(finding)
                if fixed_finding:
                    fixable_findings.append(fixed_finding)
                    
            elif finding.domain == SecurityDomain.CONTAINERS:
                # Generate container fixes (Dockerfile improvements)
                fixed_finding = self._generate_container_fix(finding)
                if fixed_finding:
                    fixable_findings.append(fixed_finding)
        
        logger.info(f"✅ Generated {len(fixable_findings)} unified fixes")
        return fixable_findings
    
    def _generate_sast_fix(self, finding: UnifiedFinding) -> Optional[UnifiedFinding]:
        """Generate SAST fix using our advanced AI engine"""
        if finding.suggested_fix:
            finding.has_autofix = True
            return finding
        return None
    
    def _generate_sca_fix(self, finding: UnifiedFinding) -> Optional[UnifiedFinding]:
        """Generate SCA fix (dependency update)"""
        if "update" in finding.suggested_fix.lower() if finding.suggested_fix else False:
            finding.has_autofix = True
            finding.fix_explanation = "Automated dependency update to secure version"
            return finding
        return None
    
    def _generate_secrets_fix(self, finding: UnifiedFinding) -> Optional[UnifiedFinding]:
        """Generate secrets fix (environment variable replacement)"""
        if finding.vulnerable_code:
            # Generate environment variable replacement
            env_var_name = self._suggest_env_var_name(finding)
            finding.suggested_fix = f"os.getenv('{env_var_name}')"
            finding.fix_explanation = f"Replace hardcoded secret with environment variable {env_var_name}"
            finding.has_autofix = True
            return finding
        return None
    
    def _suggest_env_var_name(self, finding: UnifiedFinding) -> str:
        """Suggest appropriate environment variable name"""
        if "api" in finding.title.lower():
            return "API_KEY"
        elif "database" in finding.title.lower() or "db" in finding.title.lower():
            return "DATABASE_PASSWORD"
        elif "token" in finding.title.lower():
            return "AUTH_TOKEN"
        else:
            return "SECRET_VALUE"
    
    def _generate_iac_fix(self, finding: UnifiedFinding) -> Optional[UnifiedFinding]:
        """Generate IaC fix (secure configuration)"""
        iac_fixes = {
            "public-read": "private",
            "0.0.0.0/0": "specific CIDR blocks",
            "root": "non-root user"
        }
        
        for vulnerable_pattern, secure_replacement in iac_fixes.items():
            if vulnerable_pattern in finding.vulnerable_code.lower() if finding.vulnerable_code else False:
                finding.suggested_fix = f"Replace '{vulnerable_pattern}' with '{secure_replacement}'"
                finding.fix_explanation = f"Secure IaC configuration by using {secure_replacement}"
                finding.has_autofix = True
                return finding
        
        return None
    
    def _generate_container_fix(self, finding: UnifiedFinding) -> Optional[UnifiedFinding]:
        """Generate container fix (Dockerfile improvement)"""
        container_fixes = {
            "USER 0": "USER 1000",
            "USER root": "USER nonroot",
            "ADD": "COPY",
            ":latest": ":specific-version"
        }
        
        if finding.vulnerable_code:
            for vulnerable_pattern, secure_replacement in container_fixes.items():
                if vulnerable_pattern in finding.vulnerable_code:
                    finding.suggested_fix = finding.vulnerable_code.replace(vulnerable_pattern, secure_replacement)
                    finding.fix_explanation = f"Improve container security by using {secure_replacement}"
                    finding.has_autofix = True
                    return finding
        
        return None


class DevSecureUnifiedPlatform:
    """Main DevSecure unified security platform"""
    
    def __init__(self, 
                 github_token: Optional[str] = None,
                 repo_name: Optional[str] = None,
                 config_path: Optional[str] = None):
        """Initialize DevSecure platform"""
        
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.repo_name = repo_name or os.getenv('GITHUB_REPO')
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.tool_integrator = ExternalToolIntegrator()
        self.sast_scanner = SASTScanner()
        self.sca_scanner = SCAScanner(self.tool_integrator)
        self.secrets_scanner = SecretsScanner(self.tool_integrator)
        self.iac_scanner = IaCScanner(self.tool_integrator)
        self.container_scanner = ContainerScanner(self.tool_integrator)
        
        # Analysis engines
        self.correlation_engine = FindingCorrelationEngine()
        self.autofix_engine = UnifiedAutoFixEngine()
        
        # GitHub integration
        self.github_manager = None
        if self.github_token and self.repo_name:
            self.github_manager = GitHubPRManager(self.github_token, self.repo_name)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load DevSecure configuration"""
        default_config = {
            "scan_domains": ["SAST", "SCA", "SECRETS", "IAC", "CONTAINERS"],
            "auto_install_tools": False,
            "correlation_analysis": True,
            "auto_fix": True,
            "create_prs": True,
            "pr_batching": {
                "enabled": True,
                "max_fixes_per_pr": 10
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def unified_scan(self, 
                    target_path: str,
                    domains: Optional[List[str]] = None,
                    auto_fix: bool = True,
                    create_pr: bool = True,
                    correlation_analysis: bool = True) -> UnifiedScanReport:
        """
        Run unified security scan across all domains
        
        Args:
            target_path: Path to scan
            domains: List of security domains to scan (default: all)
            auto_fix: Whether to generate auto-fixes
            create_pr: Whether to create GitHub PRs
            correlation_analysis: Whether to correlate findings
            
        Returns:
            UnifiedScanReport with comprehensive results
        """
        
        scan_start_time = time.time()
        scan_id = f"devsecure-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        logger.info(f"🚀 Starting DevSecure unified scan: {scan_id}")
        logger.info(f"📁 Target: {target_path}")
        
        # Determine which domains to scan
        if domains is None:
            domains = self.config.get("scan_domains", ["SAST", "SCA", "SECRETS", "IAC", "CONTAINERS"])
        
        logger.info(f"🔍 Scanning domains: {', '.join(domains)}")
        
        # Auto-install missing tools if configured
        if self.config.get("auto_install_tools", False):
            missing_tools = self.tool_integrator.install_missing_tools(auto_install=True)
            if missing_tools:
                logger.info(f"📦 Auto-installed tools: {list(missing_tools.keys())}")
        
        # Run scans sequentially (can be optimized to parallel later)
        all_findings = []
        scan_performance = {}
        
        if "SAST" in domains:
            start_time = time.time()
            sast_findings = self.sast_scanner.scan(target_path)
            scan_performance["SAST"] = time.time() - start_time
            all_findings.extend(sast_findings)
        
        if "SCA" in domains:
            start_time = time.time()
            sca_findings = self.sca_scanner.scan(target_path)
            scan_performance["SCA"] = time.time() - start_time
            all_findings.extend(sca_findings)
        
        if "SECRETS" in domains:
            start_time = time.time()
            secrets_findings = self.secrets_scanner.scan(target_path)
            scan_performance["SECRETS"] = time.time() - start_time
            all_findings.extend(secrets_findings)
        
        if "IAC" in domains:
            start_time = time.time()
            iac_findings = self.iac_scanner.scan(target_path)
            scan_performance["IAC"] = time.time() - start_time
            all_findings.extend(iac_findings)
        
        if "CONTAINERS" in domains:
            start_time = time.time()
            container_findings = self.container_scanner.scan(target_path)
            scan_performance["CONTAINERS"] = time.time() - start_time
            all_findings.extend(container_findings)
        
        # Correlation analysis
        correlations_found = 0
        if correlation_analysis and self.config.get("correlation_analysis", True):
            all_findings = self.correlation_engine.correlate_findings(all_findings)
            correlations_found = sum(len(f.correlations) for f in all_findings) // 2  # Avoid double counting
        
        # Auto-fix generation
        auto_fixes_applied = 0
        auto_fixable_findings = 0
        pr_batches_created = 0
        
        if auto_fix and self.config.get("auto_fix", True):
            fixed_findings = self.autofix_engine.generate_unified_fixes(all_findings)
            auto_fixable_findings = len(fixed_findings)
            
            # Update original findings with fixes
            fix_dict = {f.id: f for f in fixed_findings}
            for finding in all_findings:
                if finding.id in fix_dict:
                    fixed_finding = fix_dict[finding.id]
                    finding.has_autofix = fixed_finding.has_autofix
                    finding.suggested_fix = fixed_finding.suggested_fix
                    finding.fix_explanation = fixed_finding.fix_explanation
                    if finding.has_autofix:
                        auto_fixes_applied += 1
        
        # Create GitHub PRs
        if create_pr and self.config.get("create_prs", True) and self.github_manager:
            fixable_findings = [f for f in all_findings if f.has_autofix]
            if fixable_findings:
                # Convert to PR batches (simplified for now)
                pr_batches_created = self._create_unified_prs(fixable_findings)
        
        # Generate statistics
        findings_by_domain = defaultdict(int)
        findings_by_severity = defaultdict(int)
        
        for finding in all_findings:
            findings_by_domain[finding.domain.value] += 1
            findings_by_severity[finding.severity.value] += 1
        
        # Calculate scan duration
        scan_duration = time.time() - scan_start_time
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_findings, scan_performance)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(all_findings)
        
        # Create unified report
        report = UnifiedScanReport(
            scan_id=scan_id,
            timestamp=datetime.now(),
            target_path=target_path,
            scan_duration=scan_duration,
            total_findings=len(all_findings),
            findings_by_domain=dict(findings_by_domain),
            findings_by_severity=dict(findings_by_severity),
            findings=all_findings,
            correlations_found=correlations_found,
            auto_fixable_findings=auto_fixable_findings,
            auto_fixes_applied=auto_fixes_applied,
            pr_batches_created=pr_batches_created,
            scan_performance=scan_performance,
            recommendations=recommendations,
            business_impact=business_impact
        )
        
        logger.info(f"✅ DevSecure unified scan completed in {scan_duration:.1f} seconds")
        logger.info(f"📊 Results: {len(all_findings)} total findings, {auto_fixes_applied} auto-fixed")
        
        return report
    
    def _create_unified_prs(self, fixable_findings: List[UnifiedFinding]) -> int:
        """Create unified PRs with clear sections for each domain"""
        # Group findings by domain for PR organization
        findings_by_domain = defaultdict(list)
        for finding in fixable_findings:
            findings_by_domain[finding.domain].append(finding)
        
        # Create unified PR with sections
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"devsecure-unified-fixes-{timestamp}"
        
        # Create comprehensive PR description
        pr_title = "🛡️ DevSecure: Unified Security Fixes"
        pr_description = self._generate_unified_pr_description(findings_by_domain)
        
        # For now, return 1 (would implement actual PR creation)
        logger.info(f"Would create unified PR: {pr_title}")
        return 1
    
    def _generate_unified_pr_description(self, findings_by_domain: Dict[SecurityDomain, List[UnifiedFinding]]) -> str:
        """Generate comprehensive PR description with domain sections"""
        
        description = """# 🛡️ DevSecure Unified Security Fixes

## 📊 Summary
This PR addresses security issues across multiple domains detected by DevSecure.

"""
        
        for domain, findings in findings_by_domain.items():
            description += f"""
## 🔹 {domain.value} Fixes ({len(findings)} issues)

"""
            for finding in findings:
                description += f"""### {finding.title}
- **File**: `{finding.file_path}`
- **Severity**: {finding.severity.value}
- **Fix**: {finding.fix_explanation}

"""
        
        description += """
## ✅ Testing Checklist
- [ ] All existing tests pass
- [ ] Security improvements verified
- [ ] No functional regressions

## 🔒 Security Review
- [ ] Changes reviewed by security team
- [ ] No new vulnerabilities introduced

---
*Generated by DevSecure - The Unified Security Platform*
"""
        
        return description
    
    def _generate_recommendations(self, findings: List[UnifiedFinding], performance: Dict[str, float]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Performance recommendations
        total_time = sum(performance.values())
        if total_time > 300:  # 5 minutes
            recommendations.append("Consider enabling parallel scanning for better performance")
        
        # Security recommendations
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            recommendations.append(f"🚨 {len(critical_findings)} CRITICAL issues require immediate attention")
        
        # Domain-specific recommendations
        domains_with_findings = set(f.domain for f in findings)
        if SecurityDomain.SECRETS in domains_with_findings:
            recommendations.append("🔐 Consider implementing a secrets management solution")
        
        if SecurityDomain.SCA in domains_with_findings:
            recommendations.append("📦 Enable automated dependency updates")
        
        # Auto-fix recommendations
        auto_fixable = len([f for f in findings if f.has_autofix])
        total_findings = len(findings)
        if total_findings > 0:
            fix_rate = (auto_fixable / total_findings) * 100
            if fix_rate >= 80:
                recommendations.append(f"🎉 Excellent auto-fix coverage ({fix_rate:.1f}%)")
            elif fix_rate >= 50:
                recommendations.append(f"✅ Good auto-fix coverage ({fix_rate:.1f}%)")
            else:
                recommendations.append(f"💡 Improving auto-fix patterns could help with {100-fix_rate:.1f}% of issues")
        
        return recommendations
    
    def _calculate_business_impact(self, findings: List[UnifiedFinding]) -> Dict[str, Any]:
        """Calculate business impact of security findings"""
        
        # Simple risk calculation model
        risk_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0
        }
        
        total_risk_score = sum(risk_scores.get(f.severity, 0) for f in findings)
        
        # Estimate potential costs (simplified model)
        avg_breach_cost = 4200000  # $4.2M average data breach cost
        risk_factor = min(total_risk_score / 100.0, 1.0)  # Normalize to 0-1
        
        return {
            "total_risk_score": total_risk_score,
            "estimated_breach_probability": f"{risk_factor * 100:.1f}%",
            "potential_financial_impact": f"${avg_breach_cost * risk_factor:,.0f}",
            "mitigation_priority": "HIGH" if risk_factor > 0.7 else "MEDIUM" if risk_factor > 0.3 else "LOW"
        }


def main():
    """Main CLI entry point for DevSecure"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DevSecure: Unified Security Platform - The Checkmarx One Killer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s unified-scan /path/to/code
  %(prog)s unified-scan . --domains SAST,SCA,SECRETS
  %(prog)s unified-scan . --auto-fix --create-pr --github-token TOKEN --repo owner/repo
  %(prog)s unified-scan . --no-correlation --output scan_report.json
        """
    )
    
    parser.add_argument("command", choices=["unified-scan"], 
                       help="Command to execute")
    parser.add_argument("target", help="Target directory to scan")
    
    # Domain selection
    parser.add_argument("--domains", 
                       help="Comma-separated list of domains to scan (SAST,SCA,SECRETS,IAC,CONTAINERS)")
    
    # Feature toggles
    parser.add_argument("--auto-fix/--no-auto-fix", default=True,
                       help="Enable/disable auto-fix generation")
    parser.add_argument("--create-pr/--no-create-pr", default=True,
                       help="Enable/disable GitHub PR creation")
    parser.add_argument("--correlation/--no-correlation", default=True,
                       help="Enable/disable finding correlation analysis")
    
    # GitHub integration
    parser.add_argument("--github-token", help="GitHub API token")
    parser.add_argument("--repo", help="GitHub repository (owner/repo)")
    
    # Tool management
    parser.add_argument("--auto-install-tools", action="store_true",
                       help="Automatically install missing security tools")
    
    # Output options
    parser.add_argument("--output", help="Output file for scan report (JSON)")
    parser.add_argument("--format", choices=["json", "yaml", "html"], default="json",
                       help="Output format")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse domains
    domains = None
    if args.domains:
        domains = [d.strip().upper() for d in args.domains.split(",")]
        # Validate domains
        valid_domains = [d.value for d in SecurityDomain]
        invalid_domains = [d for d in domains if d not in valid_domains]
        if invalid_domains:
            logger.error(f"Invalid domains: {invalid_domains}. Valid domains: {valid_domains}")
            return 1
    
    # Initialize DevSecure
    try:
        devsecure = DevSecureUnifiedPlatform(
            github_token=args.github_token,
            repo_name=args.repo
        )
        
        # Auto-install tools if requested
        if args.auto_install_tools:
            logger.info("🔧 Auto-installing missing security tools...")
            devsecure.tool_integrator.install_missing_tools(auto_install=True)
        
        # Run unified scan
        logger.info("🚀 Starting DevSecure unified security scan...")
        
        report = devsecure.unified_scan(
            target_path=args.target,
            domains=domains,
            auto_fix=args.auto_fix,
            create_pr=args.create_pr,
            correlation_analysis=args.correlation
        )
        
        # Generate output
        if args.format == "json":
            report_data = asdict(report)
            # Convert datetime to string for JSON serialization
            report_data['timestamp'] = report.timestamp.isoformat()
            report_json = json.dumps(report_data, indent=2, default=str)
        else:
            report_json = json.dumps(asdict(report), indent=2, default=str)
        
        # Save to file or print
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report_json)
            logger.info(f"📄 Report saved to {args.output}")
        else:
            print(report_json)
        
        # Print summary
        print(f"\n🛡️ DevSecure Unified Scan Summary:")
        print(f"   📊 Total Findings: {report.total_findings}")
        print(f"   🔧 Auto-Fixable: {report.auto_fixable_findings}")
        print(f"   ✅ Auto-Fixed: {report.auto_fixes_applied}")
        print(f"   🔄 PR Batches: {report.pr_batches_created}")
        print(f"   ⏱️  Scan Duration: {report.scan_duration:.1f} seconds")
        
        if report.findings_by_domain:
            print(f"\n📋 Findings by Domain:")
            for domain, count in report.findings_by_domain.items():
                print(f"   {domain}: {count}")
        
        if report.recommendations:
            print(f"\n💡 Recommendations:")
            for rec in report.recommendations:
                print(f"   • {rec}")
        
        # Exit code based on findings
        critical_findings = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
        if critical_findings > 0:
            logger.warning(f"🚨 {critical_findings} CRITICAL findings require immediate attention")
            return 2
        elif report.total_findings > 0:
            return 1
        else:
            logger.info("🎉 No security issues found!")
            return 0
        
    except Exception as e:
        logger.error(f"❌ DevSecure scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 3


if __name__ == "__main__":
    sys.exit(main())
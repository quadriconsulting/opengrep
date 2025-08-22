"""
Enhanced AI Fix Engine for Opengrep
Provides 80%+ auto-fix coverage with adaptive quality based on code criticality
"""

import ast
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from abc import ABC, abstractmethod

import openai
from anthropic import Anthropic


class FixQuality(Enum):
    """Fix quality levels based on code criticality"""
    CONSERVATIVE = "conservative"  # High confidence, minimal changes
    MODERATE = "moderate"         # Balanced approach  
    AGGRESSIVE = "aggressive"     # Comprehensive fixes, lower confidence


class Severity(Enum):
    """Security severity levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeContext:
    """Context information for intelligent fix generation"""
    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    framework: Optional[str] = None  # Django, Flask, Express, Spring, etc.
    language: str = "python"
    business_criticality: str = "medium"  # low, medium, high, critical
    surrounding_code: str = ""
    dependencies: List[str] = field(default_factory=list)


@dataclass 
class SecurityFinding:
    """Security vulnerability finding from Opengrep"""
    rule_id: str
    severity: Severity
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    message: str = ""
    vulnerable_code: str = ""
    line_number: int = 0
    file_path: str = ""
    context: Optional[CodeContext] = None


@dataclass
class FixSuggestion:
    """AI-generated fix suggestion"""
    fixed_code: str
    explanation: str
    confidence: float  # 0.0 to 1.0
    test_cases: List[str] = field(default_factory=list)
    additional_changes: List[Dict[str, str]] = field(default_factory=list)
    security_impact: str = ""
    performance_impact: str = ""
    breaking_changes: bool = False


class FrameworkDetector:
    """Detects frameworks and technologies in use"""
    
    FRAMEWORK_PATTERNS = {
        'django': [r'from django', r'import django', r'Django', r'django.'],
        'flask': [r'from flask', r'import flask', r'Flask(', r'@app.route'],
        'fastapi': [r'from fastapi', r'import fastapi', r'FastAPI(', r'@app.get'],
        'express': [r'express\(\)', r'require\([\'"]express', r'app.get\(', r'app.post\('],
        'spring': [r'@RestController', r'@RequestMapping', r'import org.springframework'],
        'react': [r'import React', r'from [\'"]react', r'React.Component', r'useState'],
        'angular': [r'@Component', r'@Injectable', r'import.*@angular'],
        'vue': [r'new Vue\(', r'Vue.component', r'<template>'],
    }
    
    @classmethod
    def detect_framework(cls, code: str, file_path: str) -> Optional[str]:
        """Detect the primary framework being used"""
        code_lower = code.lower()
        
        for framework, patterns in cls.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return framework
        
        # File-based detection
        if file_path.endswith('.js') and 'package.json' in code:
            return 'nodejs'
        elif file_path.endswith('.py') and 'requirements.txt' in code:
            return 'python'
            
        return None


class BusinessCriticalityAnalyzer:
    """Analyzes business criticality of code sections"""
    
    CRITICAL_PATTERNS = [
        r'password', r'credit.*card', r'payment', r'bank', r'financial',
        r'auth', r'login', r'admin', r'privilege', r'security',
        r'medical', r'patient', r'health', r'pii', r'personal.*info'
    ]
    
    HIGH_PATTERNS = [
        r'user.*data', r'profile', r'account', r'transaction', r'order',
        r'billing', r'invoice', r'customer', r'client'
    ]
    
    @classmethod
    def analyze_criticality(cls, code: str, file_path: str) -> str:
        """Determine business criticality: low, medium, high, critical"""
        code_lower = code.lower()
        path_lower = file_path.lower()
        
        # Check for critical patterns
        for pattern in cls.CRITICAL_PATTERNS:
            if re.search(pattern, code_lower) or re.search(pattern, path_lower):
                return "critical"
        
        # Check for high patterns
        for pattern in cls.HIGH_PATTERNS:
            if re.search(pattern, code_lower) or re.search(pattern, path_lower):
                return "high"
        
        # File path analysis
        if any(x in path_lower for x in ['auth', 'security', 'admin', 'payment']):
            return "critical"
        elif any(x in path_lower for x in ['user', 'account', 'profile']):
            return "high"
        elif any(x in path_lower for x in ['test', 'mock', 'example']):
            return "low"
        
        return "medium"


class AIFixGenerator(ABC):
    """Abstract base class for AI-powered fix generation"""
    
    @abstractmethod
    def generate_fix(self, finding: SecurityFinding, quality: FixQuality) -> FixSuggestion:
        """Generate a fix suggestion for the security finding"""
        pass


class OpenAIFixGenerator(AIFixGenerator):
    """OpenAI-powered fix generation"""
    
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
    
    def generate_fix(self, finding: SecurityFinding, quality: FixQuality) -> FixSuggestion:
        """Generate fix using OpenAI GPT"""
        
        system_prompt = self._build_system_prompt(finding, quality)
        user_prompt = self._build_user_prompt(finding)
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,  # Low temperature for consistent, deterministic fixes
                max_tokens=2000
            )
            
            return self._parse_ai_response(response.choices[0].message.content, finding)
            
        except Exception as e:
            logging.error(f"OpenAI fix generation failed: {e}")
            return self._fallback_fix(finding)
    
    def _build_system_prompt(self, finding: SecurityFinding, quality: FixQuality) -> str:
        """Build system prompt based on quality level and context"""
        
        base_prompt = f"""You are an expert security engineer specializing in automated vulnerability remediation.

SECURITY CONTEXT:
- Vulnerability: {finding.rule_id}
- Severity: {finding.severity.value}
- CWE: {finding.cwe or 'Not specified'}
- OWASP: {finding.owasp or 'Not specified'}

QUALITY LEVEL: {quality.value.upper()}"""

        if quality == FixQuality.CONSERVATIVE:
            base_prompt += """
- Make MINIMAL changes that fix the vulnerability
- Prioritize HIGH CONFIDENCE solutions
- Avoid any breaking changes
- Focus on surgical precision"""
            
        elif quality == FixQuality.MODERATE:
            base_prompt += """
- Balance security improvement with code maintainability
- Include reasonable additional hardening
- Consider framework best practices
- Add basic input validation where appropriate"""
            
        elif quality == FixQuality.AGGRESSIVE:
            base_prompt += """
- Implement COMPREHENSIVE security improvements
- Add defense-in-depth measures
- Include input validation, output encoding, and monitoring
- Modernize code to current security standards"""

        framework = finding.context.framework if finding.context else None
        if framework:
            base_prompt += f"\n- Framework: {framework} - use framework-specific security patterns"

        base_prompt += """

RESPONSE FORMAT (JSON):
{
    "fixed_code": "string - The corrected code",
    "explanation": "string - Clear explanation of what was fixed and why",
    "confidence": float - 0.0 to 1.0 confidence in the fix,
    "test_cases": ["array of test cases to verify the fix"],
    "additional_changes": [{"file": "path", "change": "description"}],
    "security_impact": "string - Security improvement description",
    "performance_impact": "string - Performance impact assessment",
    "breaking_changes": boolean - Whether fix introduces breaking changes
}"""
        return base_prompt
    
    def _build_user_prompt(self, finding: SecurityFinding) -> str:
        """Build user prompt with vulnerability details"""
        
        prompt = f"""VULNERABLE CODE:
{finding.vulnerable_code}

FILE: {finding.file_path}
LINE: {finding.line_number}
MESSAGE: {finding.message}"""

        if finding.context and finding.context.surrounding_code:
            prompt += f"""

SURROUNDING CONTEXT:
{finding.context.surrounding_code}"""

        if finding.context and finding.context.framework:
            prompt += f"""

FRAMEWORK: {finding.context.framework}
IMPORTS: {', '.join(finding.context.imports)}"""

        prompt += "\n\nGenerate a secure fix following the specified quality level."
        
        return prompt
    
    def _parse_ai_response(self, response: str, finding: SecurityFinding) -> FixSuggestion:
        """Parse AI response into FixSuggestion object"""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return FixSuggestion(
                    fixed_code=data.get('fixed_code', ''),
                    explanation=data.get('explanation', ''),
                    confidence=data.get('confidence', 0.5),
                    test_cases=data.get('test_cases', []),
                    additional_changes=data.get('additional_changes', []),
                    security_impact=data.get('security_impact', ''),
                    performance_impact=data.get('performance_impact', ''),
                    breaking_changes=data.get('breaking_changes', False)
                )
            else:
                # Fallback parsing
                return FixSuggestion(
                    fixed_code=self._extract_code_block(response),
                    explanation=response[:500],
                    confidence=0.6,
                    test_cases=[],
                    additional_changes=[],
                    security_impact="AI-generated security fix",
                    performance_impact="Minimal impact expected",
                    breaking_changes=False
                )
        except Exception as e:
            logging.error(f"Failed to parse AI response: {e}")
            return self._fallback_fix(finding)
    
    def _extract_code_block(self, text: str) -> str:
        """Extract code block from AI response"""
        code_match = re.search(r'```(?:python|javascript|java|go|.*?)\n(.*?)\n```', text, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()
        return text.strip()
    
    def _fallback_fix(self, finding: SecurityFinding) -> FixSuggestion:
        """Fallback fix when AI generation fails"""
        return FixSuggestion(
            fixed_code=f"# TODO: Fix {finding.rule_id}\n{finding.vulnerable_code}",
            explanation=f"Automated fix generation failed for {finding.rule_id}. Manual review required.",
            confidence=0.1,
            test_cases=[],
            additional_changes=[],
            security_impact="Manual review required",
            performance_impact="Unknown",
            breaking_changes=False
        )


class EnhancedAutoFixEngine:
    """Main auto-fix engine with 80%+ coverage goal"""
    
    def __init__(self, ai_generator: AIFixGenerator):
        self.ai_generator = ai_generator
        self.framework_detector = FrameworkDetector()
        self.criticality_analyzer = BusinessCriticalityAnalyzer()
        self.fix_patterns = self._load_fix_patterns()
        
    def _load_fix_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load predefined fix patterns for common vulnerabilities"""
        return {
            # SQL Injection patterns
            'sql-injection': {
                'pattern': r'.*\.execute\([\'\"](.*?)[\'\"]\s*\+.*\)',
                'replacement': lambda m: f'{m.group(1).split(".")[0]}.execute("{m.group(1)}", (parameters,))',
                'confidence': 0.9,
                'frameworks': {
                    'django': 'Use Django ORM or parameterized queries',
                    'flask': 'Use SQLAlchemy parameterized queries'
                }
            },
            
            # XSS patterns  
            'xss': {
                'pattern': r'innerHTML\s*=\s*[\'\"](.*?)[\'\"]\s*\+',
                'replacement': lambda m: f'textContent = {m.group(1)}',
                'confidence': 0.8,
                'frameworks': {
                    'react': 'Use JSX with proper escaping',
                    'angular': 'Use Angular sanitization'
                }
            },
            
            # Hardcoded secrets
            'hardcoded-secret': {
                'pattern': r'(password|secret|key|token)\s*=\s*[\'\"](.*?)[\'\"]',
                'replacement': lambda m: f'{m.group(1)} = os.environ.get("{m.group(1).upper()}")',
                'confidence': 0.95,
                'frameworks': {}
            }
        }
    
    def generate_fix(self, finding: SecurityFinding, file_content: str) -> FixSuggestion:
        """Generate fix with adaptive quality based on code criticality"""
        
        # Extract context
        context = self._extract_context(finding, file_content)
        finding.context = context
        
        # Determine fix quality based on criticality
        quality = self._determine_fix_quality(context.business_criticality)
        
        # Try pattern-based fix first for common vulnerabilities
        pattern_fix = self._try_pattern_fix(finding)
        if pattern_fix and pattern_fix.confidence > 0.8:
            return pattern_fix
        
        # Use AI for complex fixes
        return self.ai_generator.generate_fix(finding, quality)
    
    def _extract_context(self, finding: SecurityFinding, file_content: str) -> CodeContext:
        """Extract comprehensive context for intelligent fixing"""
        
        lines = file_content.split('\n')
        
        # Extract surrounding code (5 lines before and after)
        start_line = max(0, finding.line_number - 6)
        end_line = min(len(lines), finding.line_number + 5)
        surrounding_code = '\n'.join(lines[start_line:end_line])
        
        # Extract imports
        imports = [line.strip() for line in lines[:50] 
                  if line.strip().startswith(('import ', 'from '))]
        
        # Detect framework
        framework = self.framework_detector.detect_framework(file_content, finding.file_path)
        
        # Analyze criticality
        criticality = self.criticality_analyzer.analyze_criticality(file_content, finding.file_path)
        
        # Extract function/class context
        function_name, class_name = self._extract_function_class_context(lines, finding.line_number)
        
        return CodeContext(
            file_path=finding.file_path,
            function_name=function_name,
            class_name=class_name,
            imports=imports,
            framework=framework,
            language=self._detect_language(finding.file_path),
            business_criticality=criticality,
            surrounding_code=surrounding_code,
            dependencies=self._extract_dependencies(file_content)
        )
    
    def _determine_fix_quality(self, criticality: str) -> FixQuality:
        """Determine fix quality based on business criticality"""
        if criticality == "critical":
            return FixQuality.CONSERVATIVE  # High confidence fixes for critical code
        elif criticality == "high":
            return FixQuality.MODERATE      # Balanced approach
        else:
            return FixQuality.AGGRESSIVE    # Comprehensive improvements for lower criticality
    
    def _try_pattern_fix(self, finding: SecurityFinding) -> Optional[FixSuggestion]:
        """Try to fix using predefined patterns"""
        
        rule_type = self._categorize_rule(finding.rule_id)
        if rule_type not in self.fix_patterns:
            return None
            
        pattern_info = self.fix_patterns[rule_type]
        pattern = pattern_info['pattern']
        
        match = re.search(pattern, finding.vulnerable_code)
        if not match:
            return None
            
        try:
            fixed_code = pattern_info['replacement'](match)
            framework_specific = ""
            
            if finding.context and finding.context.framework in pattern_info['frameworks']:
                framework_specific = pattern_info['frameworks'][finding.context.framework]
            
            return FixSuggestion(
                fixed_code=fixed_code,
                explanation=f"Pattern-based fix for {rule_type}. {framework_specific}",
                confidence=pattern_info['confidence'],
                test_cases=[f"Test {rule_type} fix with malicious input"],
                additional_changes=[],
                security_impact=f"Mitigates {rule_type} vulnerability",
                performance_impact="Minimal",
                breaking_changes=False
            )
            
        except Exception as e:
            logging.error(f"Pattern fix failed: {e}")
            return None
    
    def _categorize_rule(self, rule_id: str) -> str:
        """Categorize rule into fix pattern types"""
        rule_lower = rule_id.lower()
        
        if 'sql' in rule_lower or 'injection' in rule_lower:
            return 'sql-injection'
        elif 'xss' in rule_lower or 'cross-site' in rule_lower:
            return 'xss'
        elif 'secret' in rule_lower or 'password' in rule_lower or 'key' in rule_lower:
            return 'hardcoded-secret'
        
        return 'unknown'
    
    def _extract_function_class_context(self, lines: List[str], line_number: int) -> Tuple[Optional[str], Optional[str]]:
        """Extract function and class names containing the vulnerable code"""
        function_name = None
        class_name = None
        
        # Search backwards from vulnerable line
        for i in range(line_number - 1, -1, -1):
            line = lines[i].strip()
            
            # Python function detection
            if line.startswith('def ') and function_name is None:
                function_name = line.split('(')[0].replace('def ', '').strip()
                
            # Python class detection  
            if line.startswith('class ') and class_name is None:
                class_name = line.split('(')[0].replace('class ', '').replace(':', '').strip()
                
            # JavaScript function detection
            if ('function ' in line or '=>' in line) and function_name is None:
                if 'function ' in line:
                    function_name = line.split('function ')[1].split('(')[0].strip()
                
            if function_name and class_name:
                break
                
        return function_name, class_name
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        extension = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript', 
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c'
        }
        
        return language_map.get(extension, 'unknown')
    
    def _extract_dependencies(self, file_content: str) -> List[str]:
        """Extract dependencies from file content"""
        dependencies = []
        
        # Python imports
        for line in file_content.split('\n')[:100]:  # Check first 100 lines
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                dependencies.append(line)
                
        return dependencies[:20]  # Limit to 20 most relevant


# Example usage and testing
if __name__ == "__main__":
    # Mock OpenAI key for testing
    ai_generator = OpenAIFixGenerator("test-key")
    fix_engine = EnhancedAutoFixEngine(ai_generator)
    
    # Test with SQL injection finding
    finding = SecurityFinding(
        rule_id="python.django.security.injection.sql.sql-injection-db-cursor-execute",
        severity=Severity.HIGH,
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        message="SQL injection vulnerability detected",
        vulnerable_code='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        line_number=45,
        file_path="/app/views.py"
    )
    
    file_content = """
from django.http import HttpResponse
from django.db import connection

def get_user(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return HttpResponse("User data")
"""
    
    # Generate fix
    fix_suggestion = fix_engine.generate_fix(finding, file_content)
    print(f"Fixed code: {fix_suggestion.fixed_code}")
    print(f"Confidence: {fix_suggestion.confidence}")
    print(f"Explanation: {fix_suggestion.explanation}")
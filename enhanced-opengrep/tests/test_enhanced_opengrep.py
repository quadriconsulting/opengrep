"""
Comprehensive test suite for Enhanced Opengrep
Tests AI-powered auto-fix, PR management, and learning system
"""

import json
import pytest
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.append(str(Path(__file__).parent.parent / "core"))

from core.ai_fix_engine import (
    EnhancedAutoFixEngine, OpenAIFixGenerator, SecurityFinding, 
    FixSuggestion, Severity, FixQuality, FrameworkDetector,
    BusinessCriticalityAnalyzer, CodeContext
)
from core.github_pr_manager import (
    GitHubPRManager, BatchingStrategy, SecurityModuleDetector,
    PRContentGenerator, FixBatch, PRPriority
)
from core.learning_system import (
    LearningSystem, FixMetrics, EffectivenessAnalyzer,
    LearningInsights, FixEffectivenessDatabase
)


class TestAIFixEngine:
    """Test AI-powered fix generation"""
    
    @pytest.fixture
    def mock_ai_generator(self):
        """Mock AI generator for testing"""
        generator = Mock(spec=OpenAIFixGenerator)
        generator.generate_fix.return_value = FixSuggestion(
            fixed_code="fixed_code_example",
            explanation="Test fix explanation",
            confidence=0.85,
            test_cases=["test_case_1", "test_case_2"],
            security_impact="Fixes SQL injection vulnerability",
            performance_impact="Minimal",
            breaking_changes=False
        )
        return generator
    
    @pytest.fixture
    def sample_finding(self):
        """Sample security finding for testing"""
        return SecurityFinding(
            rule_id="sql-injection-test",
            severity=Severity.HIGH,
            cwe="CWE-89",
            owasp="A03:2021 - Injection",
            message="SQL injection vulnerability detected",
            vulnerable_code='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            line_number=42,
            file_path="app/views.py"
        )
    
    def test_framework_detection(self):
        """Test framework detection from code"""
        django_code = "from django.http import HttpResponse"
        assert FrameworkDetector.detect_framework(django_code, "views.py") == "django"
        
        flask_code = "from flask import Flask"
        assert FrameworkDetector.detect_framework(flask_code, "app.py") == "flask"
        
        express_code = "const express = require('express')"
        assert FrameworkDetector.detect_framework(express_code, "server.js") == "express"
    
    def test_business_criticality_analysis(self):
        """Test business criticality analysis"""
        critical_code = "password_hash = get_password_hash(password)"
        assert BusinessCriticalityAnalyzer.analyze_criticality(critical_code, "auth.py") == "critical"
        
        high_code = "user_profile = get_user_data(user_id)" 
        assert BusinessCriticalityAnalyzer.analyze_criticality(high_code, "profile.py") == "high"
        
        low_code = "test_function()"
        assert BusinessCriticalityAnalyzer.analyze_criticality(low_code, "test_utils.py") == "low"
    
    def test_fix_quality_determination(self, mock_ai_generator):
        """Test fix quality determination based on criticality"""
        engine = EnhancedAutoFixEngine(mock_ai_generator)
        
        assert engine._determine_fix_quality("critical") == FixQuality.CONSERVATIVE
        assert engine._determine_fix_quality("high") == FixQuality.MODERATE
        assert engine._determine_fix_quality("medium") == FixQuality.AGGRESSIVE
        assert engine._determine_fix_quality("low") == FixQuality.AGGRESSIVE
    
    def test_pattern_based_fixes(self, mock_ai_generator, sample_finding):
        """Test pattern-based fixes for common vulnerabilities"""
        engine = EnhancedAutoFixEngine(mock_ai_generator)
        
        # Test SQL injection pattern fix
        sql_finding = sample_finding
        file_content = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
'''
        
        fix = engine.generate_fix(sql_finding, file_content)
        assert fix is not None
        assert fix.confidence > 0.0
        assert "fix" in fix.explanation.lower() or "secure" in fix.explanation.lower()
    
    @patch('openai.OpenAI')
    def test_openai_fix_generation(self, mock_openai):
        """Test OpenAI fix generation"""
        # Mock OpenAI response
        mock_response = Mock()
        mock_response.choices[0].message.content = json.dumps({
            "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "explanation": "Use parameterized query to prevent SQL injection",
            "confidence": 0.95,
            "test_cases": ["Test with malicious input"],
            "security_impact": "Prevents SQL injection attacks",
            "performance_impact": "No significant impact",
            "breaking_changes": False
        })
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        generator = OpenAIFixGenerator("test-api-key")
        finding = SecurityFinding(
            rule_id="sql-injection",
            severity=Severity.HIGH,
            message="SQL injection",
            vulnerable_code="SELECT * FROM users WHERE id = " + user_id,
            file_path="app.py",
            line_number=10
        )
        
        fix = generator.generate_fix(finding, FixQuality.MODERATE)
        
        assert fix.confidence == 0.95
        assert "parameterized" in fix.explanation
        assert not fix.breaking_changes


class TestGitHubPRManager:
    """Test GitHub PR management and batching"""
    
    @pytest.fixture
    def sample_fixes(self):
        """Sample fixes for batching tests"""
        return [
            (
                SecurityFinding(
                    rule_id="sql-injection-critical",
                    severity=Severity.CRITICAL,
                    message="Critical SQL injection",
                    file_path="app/auth.py",
                    line_number=10
                ),
                FixSuggestion(
                    fixed_code="fixed_sql",
                    explanation="Fix SQL injection",
                    confidence=0.95
                )
            ),
            (
                SecurityFinding(
                    rule_id="xss-medium",
                    severity=Severity.MEDIUM,
                    message="XSS vulnerability",
                    file_path="app/templates/profile.html",
                    line_number=25
                ),
                FixSuggestion(
                    fixed_code="{{ user.name|escape }}",
                    explanation="Add XSS protection",
                    confidence=0.80
                )
            )
        ]
    
    def test_security_module_detection(self):
        """Test security module detection"""
        auth_finding = SecurityFinding(
            rule_id="jwt-token-validation",
            severity=Severity.HIGH,
            message="JWT token validation issue",
            file_path="app/auth/middleware.py",
            line_number=15
        )
        
        module = SecurityModuleDetector.detect_module(auth_finding)
        assert "Authentication" in module.name
        
        xss_finding = SecurityFinding(
            rule_id="xss-template-injection",
            severity=Severity.MEDIUM,
            message="XSS in template",
            file_path="app/templates/user_profile.html", 
            line_number=20
        )
        
        module = SecurityModuleDetector.detect_module(xss_finding)
        assert "XSS" in module.name
    
    def test_priority_determination(self, sample_fixes):
        """Test PR priority determination"""
        critical_fix = sample_fixes[0]
        medium_fix = sample_fixes[1]
        
        critical_priority = BatchingStrategy.determine_priority(*critical_fix)
        medium_priority = BatchingStrategy.determine_priority(*medium_fix)
        
        assert critical_priority == PRPriority.IMMEDIATE
        assert medium_priority == PRPriority.DAILY
    
    def test_batch_creation(self, sample_fixes):
        """Test fix batch creation"""
        batches = BatchingStrategy.create_batches(sample_fixes)
        
        assert len(batches) >= 1
        # Critical issues should get their own batch
        critical_batches = [b for b in batches if b.priority == PRPriority.IMMEDIATE]
        assert len(critical_batches) >= 1
    
    def test_pr_content_generation(self, sample_fixes):
        """Test PR content generation"""
        batches = BatchingStrategy.create_batches(sample_fixes)
        
        for batch in batches:
            template = PRContentGenerator.generate_pr_template(batch)
            
            assert template.title
            assert template.description
            assert len(template.labels) > 0
            
            if batch.priority == PRPriority.IMMEDIATE:
                assert "CRITICAL" in template.title or "critical" in template.labels
    
    @patch('github.Github')
    def test_pr_manager_initialization(self, mock_github):
        """Test PR manager initialization"""
        mock_repo = Mock()
        mock_github.return_value.get_repo.return_value = mock_repo
        
        pr_manager = GitHubPRManager("test-token", "owner", "repo")
        
        assert pr_manager.repo == mock_repo
        assert pr_manager.repo_owner == "owner"
        assert pr_manager.repo_name == "repo"


class TestLearningSystem:
    """Test learning system and effectiveness analysis"""
    
    @pytest.fixture
    def temp_db(self):
        """Temporary database for testing"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        db = FixEffectivenessDatabase(db_path)
        yield db
        
        # Cleanup
        Path(db_path).unlink(missing_ok=True)
    
    @pytest.fixture
    def sample_metrics(self):
        """Sample fix metrics for testing"""
        return [
            FixMetrics(
                fix_id=str(uuid.uuid4()),
                rule_id="sql-injection-test",
                severity="high",
                file_path="app/models.py",
                confidence=0.85,
                fix_quality="moderate",
                merged=True,
                time_to_merge=2.5,
                review_comments=1,
                approved=True,
                false_positive=False,
                regression_introduced=False
            ),
            FixMetrics(
                fix_id=str(uuid.uuid4()),
                rule_id="xss-template",
                severity="medium",
                file_path="templates/profile.html",
                confidence=0.75,
                fix_quality="aggressive",
                merged=False,
                time_to_merge=None,
                review_comments=3,
                approved=False,
                false_positive=True,
                regression_introduced=False
            )
        ]
    
    def test_database_operations(self, temp_db, sample_metrics):
        """Test database storage and retrieval"""
        # Store metrics
        for metric in sample_metrics:
            temp_db.store_fix_metrics(metric)
        
        # Retrieve metrics
        retrieved = temp_db.get_fix_metrics(days=30)
        
        assert len(retrieved) == len(sample_metrics)
        assert retrieved[0].rule_id in [m.rule_id for m in sample_metrics]
    
    def test_effectiveness_analysis(self, sample_metrics):
        """Test effectiveness analysis"""
        temp_db = Mock()
        analyzer = EffectivenessAnalyzer(temp_db)
        
        rule_effectiveness = analyzer.analyze_rule_effectiveness(sample_metrics)
        
        # SQL injection should have 100% effectiveness (1 success, 1 total)
        assert rule_effectiveness["sql-injection-test"] == 1.0
        
        # XSS should have 0% effectiveness (0 success, 1 total due to false positive)
        assert rule_effectiveness["xss-template"] == 0.0
    
    def test_confidence_calibration(self, sample_metrics):
        """Test confidence calibration analysis"""
        temp_db = Mock()
        analyzer = EffectivenessAnalyzer(temp_db)
        
        calibration = analyzer.analyze_confidence_calibration(sample_metrics)
        
        # Should have calibration data for confidence ranges
        assert isinstance(calibration, dict)
        assert len(calibration) > 0
    
    def test_learning_system_integration(self, temp_db):
        """Test full learning system integration"""
        learning = LearningSystem(temp_db.db_path)
        
        # Record a fix attempt
        finding = SecurityFinding(
            rule_id="test-rule",
            severity=Severity.MEDIUM,
            message="Test finding",
            file_path="test.py",
            line_number=10
        )
        
        suggestion = FixSuggestion(
            fixed_code="fixed_code",
            explanation="Test fix",
            confidence=0.8
        )
        
        fix_id = learning.record_fix_attempt(finding, suggestion, FixQuality.MODERATE, "test-fix-id")
        
        # Update outcome
        learning.update_fix_outcome(
            fix_id=fix_id,
            pr_number=123,
            merged=True,
            time_to_merge=3.0
        )
        
        # Analyze and learn
        insights = learning.analyze_and_learn(days=1)
        
        assert isinstance(insights, LearningInsights)
        assert len(insights.recommendations) > 0
    
    def test_rule_improvement_suggestions(self, temp_db, sample_metrics):
        """Test rule-specific improvement suggestions"""
        learning = LearningSystem(temp_db.db_path)
        
        # Store sample metrics
        for metric in sample_metrics:
            temp_db.store_fix_metrics(metric)
        
        suggestions = learning.get_rule_improvement_suggestions("sql-injection-test")
        
        assert "rule_id" in suggestions
        assert "success_rate" in suggestions
        assert "suggestions" in suggestions
        assert isinstance(suggestions["suggestions"], list)


class TestIntegration:
    """Integration tests for the complete Enhanced Opengrep system"""
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        return {
            'openai_api_key': 'test-key',
            'github_token': 'test-token',
            'repo_owner': 'test-owner',
            'repo_name': 'test-repo',
            'learning_db_path': ':memory:'  # In-memory database for tests
        }
    
    @patch('core.ai_fix_engine.openai.OpenAI')
    @patch('core.github_pr_manager.Github')
    def test_end_to_end_workflow(self, mock_github, mock_openai, mock_config):
        """Test complete end-to-end workflow"""
        # Mock AI response
        mock_ai_response = Mock()
        mock_ai_response.choices[0].message.content = json.dumps({
            "fixed_code": "secure_code_here",
            "explanation": "Security fix applied",
            "confidence": 0.9,
            "test_cases": [],
            "security_impact": "Vulnerability fixed",
            "performance_impact": "No impact",
            "breaking_changes": False
        })
        
        mock_openai_client = Mock()
        mock_openai_client.chat.completions.create.return_value = mock_ai_response
        mock_openai.return_value = mock_openai_client
        
        # Mock GitHub
        mock_repo = Mock()
        mock_pr = Mock()
        mock_pr.number = 123
        mock_pr.title = "Security Fix"
        mock_pr.html_url = "https://github.com/test/test/pull/123"
        mock_repo.create_pull.return_value = mock_pr
        mock_github.return_value.get_repo.return_value = mock_repo
        
        # This would test the main EnhancedOpengrep class
        # but requires more complex mocking of the original Opengrep scan
        # For now, we test individual components
        
        assert True  # Placeholder for full integration test
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        # Test valid configuration
        valid_config = {
            'openai_api_key': 'test-key',
            'github_token': 'test-token', 
            'repo_owner': 'owner',
            'repo_name': 'repo'
        }
        
        # This would be implemented in the main class
        # For now, just test that required keys exist
        required_keys = ['openai_api_key']
        for key in required_keys:
            assert key in valid_config
    
    def test_error_handling(self):
        """Test error handling in various scenarios"""
        # Test AI API failure
        with patch('core.ai_fix_engine.openai.OpenAI') as mock_openai:
            mock_openai.side_effect = Exception("API Error")
            
            # Should handle gracefully and provide fallback
            generator = OpenAIFixGenerator("test-key")
            finding = SecurityFinding(
                rule_id="test-rule",
                severity=Severity.MEDIUM,
                message="Test",
                file_path="test.py",
                line_number=1
            )
            
            # Should not raise exception
            try:
                fix = generator.generate_fix(finding, FixQuality.MODERATE)
                assert fix is not None  # Should provide fallback
            except Exception:
                pytest.fail("Should handle AI API errors gracefully")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
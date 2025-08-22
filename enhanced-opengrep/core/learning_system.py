"""
Learning System for Enhanced Opengrep
Learns from fix effectiveness metrics to improve future auto-fixes
"""

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import statistics
import numpy as np
from collections import defaultdict, Counter

from .ai_fix_engine import SecurityFinding, FixSuggestion, Severity, FixQuality
from .github_pr_manager import PRPriority


@dataclass
class FixMetrics:
    """Metrics for a specific fix application"""
    fix_id: str
    rule_id: str
    severity: str
    file_path: str
    confidence: float
    fix_quality: str  # FixQuality enum value
    
    # GitHub PR metrics
    pr_number: Optional[int] = None
    time_to_merge: Optional[float] = None  # hours
    review_comments: int = 0
    changes_requested: int = 0
    approved: bool = False
    merged: bool = False
    reverted: bool = False
    
    # Effectiveness metrics
    false_positive: bool = False
    regression_introduced: bool = False
    security_test_passed: bool = True
    developer_satisfaction: Optional[int] = None  # 1-5 rating
    
    # Timestamps
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        self.updated_at = datetime.now()


@dataclass
class LearningInsights:
    """Insights derived from fix effectiveness analysis"""
    rule_effectiveness: Dict[str, float]  # rule_id -> success rate
    quality_performance: Dict[str, Dict[str, float]]  # quality -> metrics
    framework_preferences: Dict[str, List[str]]  # framework -> preferred patterns
    developer_feedback_trends: Dict[str, float]  # metric -> trend
    recommendations: List[str]
    confidence_calibration: Dict[str, float]  # confidence_range -> actual_success_rate


class FixEffectivenessDatabase:
    """SQLite database for storing fix metrics and learning data"""
    
    def __init__(self, db_path: str = "fix_effectiveness.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fix_metrics (
                    fix_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    fix_quality TEXT NOT NULL,
                    pr_number INTEGER,
                    time_to_merge REAL,
                    review_comments INTEGER DEFAULT 0,
                    changes_requested INTEGER DEFAULT 0,
                    approved BOOLEAN DEFAULT FALSE,
                    merged BOOLEAN DEFAULT FALSE,
                    reverted BOOLEAN DEFAULT FALSE,
                    false_positive BOOLEAN DEFAULT FALSE,
                    regression_introduced BOOLEAN DEFAULT FALSE,
                    security_test_passed BOOLEAN DEFAULT TRUE,
                    developer_satisfaction INTEGER,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_patterns (
                    rule_id TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP NOT NULL,
                    PRIMARY KEY (rule_id, pattern_type)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learning_insights (
                    insight_date DATE PRIMARY KEY,
                    insights_data TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_id ON fix_metrics(rule_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON fix_metrics(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON fix_metrics(created_at)")
    
    def store_fix_metrics(self, metrics: FixMetrics):
        """Store fix metrics in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO fix_metrics (
                    fix_id, rule_id, severity, file_path, confidence, fix_quality,
                    pr_number, time_to_merge, review_comments, changes_requested,
                    approved, merged, reverted, false_positive, regression_introduced,
                    security_test_passed, developer_satisfaction, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metrics.fix_id, metrics.rule_id, metrics.severity, metrics.file_path,
                metrics.confidence, metrics.fix_quality, metrics.pr_number,
                metrics.time_to_merge, metrics.review_comments, metrics.changes_requested,
                metrics.approved, metrics.merged, metrics.reverted, metrics.false_positive,
                metrics.regression_introduced, metrics.security_test_passed,
                metrics.developer_satisfaction, metrics.created_at, metrics.updated_at
            ))
    
    def get_fix_metrics(self, days: int = 30) -> List[FixMetrics]:
        """Get fix metrics from the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM fix_metrics 
                WHERE created_at >= ? 
                ORDER BY created_at DESC
            """, (cutoff_date,))
            
            metrics = []
            for row in cursor.fetchall():
                metrics.append(FixMetrics(
                    fix_id=row['fix_id'],
                    rule_id=row['rule_id'],
                    severity=row['severity'],
                    file_path=row['file_path'],
                    confidence=row['confidence'],
                    fix_quality=row['fix_quality'],
                    pr_number=row['pr_number'],
                    time_to_merge=row['time_to_merge'],
                    review_comments=row['review_comments'],
                    changes_requested=row['changes_requested'],
                    approved=bool(row['approved']),
                    merged=bool(row['merged']),
                    reverted=bool(row['reverted']),
                    false_positive=bool(row['false_positive']),
                    regression_introduced=bool(row['regression_introduced']),
                    security_test_passed=bool(row['security_test_passed']),
                    developer_satisfaction=row['developer_satisfaction'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    updated_at=datetime.fromisoformat(row['updated_at'])
                ))
            
            return metrics
    
    def store_learning_insights(self, insights: LearningInsights):
        """Store learning insights for a date"""
        insight_date = datetime.now().date()
        insights_json = json.dumps(asdict(insights), default=str)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO learning_insights (insight_date, insights_data, created_at)
                VALUES (?, ?, ?)
            """, (insight_date, insights_json, datetime.now()))
    
    def get_latest_insights(self) -> Optional[LearningInsights]:
        """Get the most recent learning insights"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT insights_data FROM learning_insights 
                ORDER BY insight_date DESC LIMIT 1
            """)
            
            row = cursor.fetchone()
            if row:
                data = json.loads(row['insights_data'])
                return LearningInsights(**data)
        
        return None


class EffectivenessAnalyzer:
    """Analyzes fix effectiveness and generates insights"""
    
    def __init__(self, database: FixEffectivenessDatabase):
        self.db = database
    
    def analyze_rule_effectiveness(self, metrics: List[FixMetrics]) -> Dict[str, float]:
        """Analyze effectiveness by rule type"""
        rule_stats = defaultdict(lambda: {'success': 0, 'total': 0})
        
        for metric in metrics:
            rule_stats[metric.rule_id]['total'] += 1
            
            # Define success criteria
            is_successful = (
                not metric.false_positive and
                not metric.regression_introduced and
                metric.security_test_passed and
                (metric.merged or metric.approved or metric.time_to_merge is not None)
            )
            
            if is_successful:
                rule_stats[metric.rule_id]['success'] += 1
        
        # Calculate success rates
        effectiveness = {}
        for rule_id, stats in rule_stats.items():
            if stats['total'] > 0:
                effectiveness[rule_id] = stats['success'] / stats['total']
        
        return effectiveness
    
    def analyze_quality_performance(self, metrics: List[FixMetrics]) -> Dict[str, Dict[str, float]]:
        """Analyze performance by fix quality level"""
        quality_stats = defaultdict(lambda: {
            'merge_rate': [],
            'time_to_merge': [],
            'review_comments': [],
            'false_positive_rate': [],
            'satisfaction': []
        })
        
        for metric in metrics:
            quality = metric.fix_quality
            
            quality_stats[quality]['merge_rate'].append(1 if metric.merged else 0)
            
            if metric.time_to_merge is not None:
                quality_stats[quality]['time_to_merge'].append(metric.time_to_merge)
            
            quality_stats[quality]['review_comments'].append(metric.review_comments)
            quality_stats[quality]['false_positive_rate'].append(1 if metric.false_positive else 0)
            
            if metric.developer_satisfaction is not None:
                quality_stats[quality]['satisfaction'].append(metric.developer_satisfaction)
        
        # Calculate averages
        performance = {}
        for quality, stats in quality_stats.items():
            performance[quality] = {}
            
            for metric_name, values in stats.items():
                if values:
                    if metric_name in ['merge_rate', 'false_positive_rate']:
                        performance[quality][metric_name] = statistics.mean(values)
                    else:
                        performance[quality][metric_name] = {
                            'mean': statistics.mean(values),
                            'median': statistics.median(values),
                            'std': statistics.stdev(values) if len(values) > 1 else 0
                        }
        
        return performance
    
    def analyze_confidence_calibration(self, metrics: List[FixMetrics]) -> Dict[str, float]:
        """Analyze how well confidence scores predict actual success"""
        confidence_ranges = {
            '0.0-0.2': (0.0, 0.2),
            '0.2-0.4': (0.2, 0.4), 
            '0.4-0.6': (0.4, 0.6),
            '0.6-0.8': (0.6, 0.8),
            '0.8-1.0': (0.8, 1.0)
        }
        
        calibration = {}
        
        for range_name, (min_conf, max_conf) in confidence_ranges.items():
            range_metrics = [
                m for m in metrics 
                if min_conf <= m.confidence < max_conf
            ]
            
            if range_metrics:
                success_count = sum(
                    1 for m in range_metrics
                    if not m.false_positive and not m.regression_introduced
                )
                calibration[range_name] = success_count / len(range_metrics)
            else:
                calibration[range_name] = 0.0
        
        return calibration
    
    def detect_framework_preferences(self, metrics: List[FixMetrics]) -> Dict[str, List[str]]:
        """Detect which fix patterns work best for each framework"""
        # This would analyze file paths and fix patterns to determine preferences
        # Simplified version for now
        framework_patterns = defaultdict(lambda: defaultdict(int))
        
        for metric in metrics:
            # Detect framework from file path
            framework = self._detect_framework_from_path(metric.file_path)
            
            if framework and metric.merged and not metric.false_positive:
                # In a real implementation, we'd track specific fix patterns
                framework_patterns[framework][metric.rule_id] += 1
        
        preferences = {}
        for framework, patterns in framework_patterns.items():
            # Sort by success count and take top patterns
            top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]
            preferences[framework] = [pattern for pattern, count in top_patterns]
        
        return preferences
    
    def _detect_framework_from_path(self, file_path: str) -> Optional[str]:
        """Detect framework from file path patterns"""
        path_lower = file_path.lower()
        
        if 'django' in path_lower or 'manage.py' in path_lower:
            return 'django'
        elif 'flask' in path_lower or 'app.py' in path_lower:
            return 'flask'
        elif 'express' in path_lower or 'node_modules' in path_lower:
            return 'express'
        elif 'spring' in path_lower or '.java' in path_lower:
            return 'spring'
        elif 'react' in path_lower or 'jsx' in path_lower:
            return 'react'
        
        return None
    
    def generate_recommendations(self, insights: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Rule effectiveness recommendations
        rule_effectiveness = insights.get('rule_effectiveness', {})
        if rule_effectiveness:
            low_performing_rules = [
                rule for rule, effectiveness in rule_effectiveness.items()
                if effectiveness < 0.7
            ]
            
            if low_performing_rules:
                recommendations.append(
                    f"Consider improving fix patterns for rules with low effectiveness: {', '.join(low_performing_rules[:3])}"
                )
        
        # Quality performance recommendations
        quality_performance = insights.get('quality_performance', {})
        if quality_performance:
            for quality, metrics in quality_performance.items():
                merge_rate = metrics.get('merge_rate', 0)
                if merge_rate < 0.8:
                    recommendations.append(
                        f"Improve {quality} quality fixes - current merge rate: {merge_rate:.1%}"
                    )
        
        # Confidence calibration recommendations
        confidence_calibration = insights.get('confidence_calibration', {})
        if confidence_calibration:
            for range_name, actual_rate in confidence_calibration.items():
                expected_rate = (float(range_name.split('-')[0]) + float(range_name.split('-')[1])) / 2
                if abs(actual_rate - expected_rate) > 0.2:
                    recommendations.append(
                        f"Recalibrate confidence scoring for range {range_name} - predicted: {expected_rate:.1%}, actual: {actual_rate:.1%}"
                    )
        
        # General recommendations
        if not recommendations:
            recommendations.append("Fix effectiveness is performing well. Continue monitoring.")
        
        return recommendations


class LearningSystem:
    """Main learning system that coordinates analysis and improvement"""
    
    def __init__(self, db_path: str = "fix_effectiveness.db"):
        self.db = FixEffectivenessDatabase(db_path)
        self.analyzer = EffectivenessAnalyzer(self.db)
        self.logger = logging.getLogger(__name__)
    
    def record_fix_attempt(self, finding: SecurityFinding, suggestion: FixSuggestion, 
                          fix_quality: FixQuality, fix_id: str) -> str:
        """Record a fix attempt for future analysis"""
        
        metrics = FixMetrics(
            fix_id=fix_id,
            rule_id=finding.rule_id,
            severity=finding.severity.value,
            file_path=finding.file_path,
            confidence=suggestion.confidence,
            fix_quality=fix_quality.value
        )
        
        self.db.store_fix_metrics(metrics)
        self.logger.info(f"Recorded fix attempt: {fix_id}")
        
        return fix_id
    
    def update_fix_outcome(self, fix_id: str, pr_number: int = None, 
                          merged: bool = False, time_to_merge: float = None,
                          review_comments: int = 0, approved: bool = False,
                          false_positive: bool = False, regression: bool = False):
        """Update fix outcome after PR processing"""
        
        # Get existing metrics
        metrics = self._get_fix_metrics_by_id(fix_id)
        if not metrics:
            self.logger.warning(f"Fix metrics not found for ID: {fix_id}")
            return
        
        # Update with new information
        metrics.pr_number = pr_number
        metrics.merged = merged
        metrics.time_to_merge = time_to_merge
        metrics.review_comments = review_comments
        metrics.approved = approved
        metrics.false_positive = false_positive
        metrics.regression_introduced = regression
        metrics.updated_at = datetime.now()
        
        self.db.store_fix_metrics(metrics)
        self.logger.info(f"Updated fix outcome: {fix_id}")
    
    def analyze_and_learn(self, days: int = 30) -> LearningInsights:
        """Analyze recent fixes and generate learning insights"""
        
        # Get recent metrics
        metrics = self.db.get_fix_metrics(days)
        
        if not metrics:
            self.logger.warning("No fix metrics available for analysis")
            return LearningInsights(
                rule_effectiveness={},
                quality_performance={},
                framework_preferences={},
                developer_feedback_trends={},
                recommendations=["No data available for analysis"],
                confidence_calibration={}
            )
        
        self.logger.info(f"Analyzing {len(metrics)} fix metrics from last {days} days")
        
        # Perform various analyses
        rule_effectiveness = self.analyzer.analyze_rule_effectiveness(metrics)
        quality_performance = self.analyzer.analyze_quality_performance(metrics)
        confidence_calibration = self.analyzer.analyze_confidence_calibration(metrics)
        framework_preferences = self.analyzer.detect_framework_preferences(metrics)
        
        # Generate insights
        insights_data = {
            'rule_effectiveness': rule_effectiveness,
            'quality_performance': quality_performance,
            'confidence_calibration': confidence_calibration,
            'framework_preferences': framework_preferences
        }
        
        recommendations = self.analyzer.generate_recommendations(insights_data)
        
        insights = LearningInsights(
            rule_effectiveness=rule_effectiveness,
            quality_performance=quality_performance,
            framework_preferences=framework_preferences,
            developer_feedback_trends={},  # Could be expanded
            recommendations=recommendations,
            confidence_calibration=confidence_calibration
        )
        
        # Store insights
        self.db.store_learning_insights(insights)
        
        self.logger.info(f"Generated {len(recommendations)} recommendations")
        return insights
    
    def get_rule_improvement_suggestions(self, rule_id: str) -> Dict[str, Any]:
        """Get specific improvement suggestions for a rule"""
        
        metrics = self.db.get_fix_metrics(90)  # Last 90 days
        rule_metrics = [m for m in metrics if m.rule_id == rule_id]
        
        if not rule_metrics:
            return {'suggestion': 'No historical data available for this rule'}
        
        # Calculate statistics
        success_rate = sum(1 for m in rule_metrics if m.merged and not m.false_positive) / len(rule_metrics)
        avg_confidence = statistics.mean(m.confidence for m in rule_metrics)
        avg_review_comments = statistics.mean(m.review_comments for m in rule_metrics)
        
        suggestions = []
        
        if success_rate < 0.7:
            suggestions.append(f"Success rate is low ({success_rate:.1%}). Consider improving fix patterns.")
        
        if avg_confidence < 0.6:
            suggestions.append(f"Average confidence is low ({avg_confidence:.1%}). Review fix generation logic.")
        
        if avg_review_comments > 5:
            suggestions.append(f"High review comments ({avg_review_comments:.1f} avg). Fixes may need more context.")
        
        return {
            'rule_id': rule_id,
            'success_rate': success_rate,
            'avg_confidence': avg_confidence,
            'avg_review_comments': avg_review_comments,
            'total_attempts': len(rule_metrics),
            'suggestions': suggestions or ['Rule performance is satisfactory']
        }
    
    def _get_fix_metrics_by_id(self, fix_id: str) -> Optional[FixMetrics]:
        """Get fix metrics by fix ID"""
        metrics = self.db.get_fix_metrics(365)  # Last year
        for metric in metrics:
            if metric.fix_id == fix_id:
                return metric
        return None
    
    def export_learning_data(self, output_path: str):
        """Export learning data for external analysis"""
        insights = self.db.get_latest_insights()
        metrics = self.db.get_fix_metrics(90)
        
        export_data = {
            'insights': asdict(insights) if insights else None,
            'metrics': [asdict(m) for m in metrics],
            'exported_at': datetime.now().isoformat()
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        self.logger.info(f"Exported learning data to {output_path}")


# Example usage and testing
if __name__ == "__main__":
    import uuid
    from ai_fix_engine import SecurityFinding, FixSuggestion, Severity, FixQuality
    
    # Initialize learning system
    learning = LearningSystem("test_learning.db")
    
    # Simulate fix attempts
    finding = SecurityFinding(
        rule_id="sql-injection-test",
        severity=Severity.HIGH,
        message="Test SQL injection",
        file_path="app/models.py",
        line_number=42
    )
    
    suggestion = FixSuggestion(
        fixed_code="User.objects.filter(id=user_id)",
        explanation="Use ORM instead of raw SQL",
        confidence=0.85
    )
    
    # Record fix attempt
    fix_id = str(uuid.uuid4())
    learning.record_fix_attempt(finding, suggestion, FixQuality.MODERATE, fix_id)
    
    # Simulate successful outcome
    learning.update_fix_outcome(
        fix_id=fix_id,
        pr_number=123,
        merged=True,
        time_to_merge=4.5,
        review_comments=2,
        approved=True
    )
    
    # Analyze and learn
    insights = learning.analyze_and_learn(days=7)
    print(f"Generated {len(insights.recommendations)} recommendations:")
    for rec in insights.recommendations:
        print(f"- {rec}")
    
    # Get rule-specific suggestions
    suggestions = learning.get_rule_improvement_suggestions("sql-injection-test")
    print(f"\nRule suggestions: {suggestions}")
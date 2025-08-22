# DevSecure Project Structure

## Directory Layout

```
devsecure/
├── README.md
├── requirements.txt
├── requirements-dev.txt
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── .gitignore
├── setup.py
├── pytest.ini
├── mypy.ini
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── deploy.yml
├── docs/
│   ├── api/
│   ├── user-guide/
│   ├── developer-guide/
│   └── deployment/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── fixtures/
│       └── test_repos/
├── config/
│   ├── development.yaml
│   ├── testing.yaml
│   ├── production.yaml
│   └── rules/
│       ├── sast_rules.yaml
│       ├── secrets_patterns.yaml
│       └── iac_policies.yaml
├── scripts/
│   ├── setup.sh
│   ├── migrate.py
│   ├── seed_data.py
│   └── performance_test.py
├── devsecure/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── database.py
│   │   ├── config.py
│   │   └── exceptions.py
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── sast/
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py
│   │   │   ├── parsers/
│   │   │   └── rules/
│   │   ├── sca/
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py
│   │   │   ├── package_managers/
│   │   │   └── vulnerability_db.py
│   │   ├── secrets/
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py
│   │   │   ├── patterns.py
│   │   │   └── entropy.py
│   │   ├── iac/
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py
│   │   │   ├── terraform/
│   │   │   ├── cloudformation/
│   │   │   └── kubernetes/
│   │   └── container/
│   │       ├── __init__.py
│   │       ├── analyzer.py
│   │       ├── dockerfile_parser.py
│   │       └── image_scanner.py
│   ├── autofix/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── patterns/
│   │   │   ├── __init__.py
│   │   │   ├── sast_fixes.py
│   │   │   ├── sca_fixes.py
│   │   │   ├── secrets_fixes.py
│   │   │   ├── iac_fixes.py
│   │   │   └── container_fixes.py
│   │   ├── ai/
│   │   │   ├── __init__.py
│   │   │   ├── codegen.py
│   │   │   └── validation.py
│   │   └── context/
│   │       ├── __init__.py
│   │       ├── code_analyzer.py
│   │       └── test_runner.py
│   ├── github/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── pr_manager.py
│   │   ├── batcher.py
│   │   └── tracker.py
│   ├── correlation/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── deduplicator.py
│   │   └── risk_analyzer.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── auth/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   └── routes.py
│   │   ├── scans/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   ├── routes.py
│   │   │   └── tasks.py
│   │   ├── findings/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   └── routes.py
│   │   ├── autofix/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   └── routes.py
│   │   └── metrics/
│   │       ├── __init__.py
│   │       ├── models.py
│   │       └── routes.py
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── scan_worker.py
│   │   ├── fix_worker.py
│   │   └── github_worker.py
│   └── cli/
│       ├── __init__.py
│       ├── main.py
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── scan.py
│       │   ├── fix.py
│       │   └── config.py
│       └── utils/
├── dashboard/
│   ├── package.json
│   ├── webpack.config.js
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.tsx
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── common/
│   │   │   ├── dashboard/
│   │   │   ├── scans/
│   │   │   ├── findings/
│   │   │   ├── autofix/
│   │   │   └── correlation/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Scans.tsx
│   │   │   ├── Findings.tsx
│   │   │   ├── AutoFix.tsx
│   │   │   └── Settings.tsx
│   │   ├── services/
│   │   │   ├── api.ts
│   │   │   ├── websocket.ts
│   │   │   └── auth.ts
│   │   ├── store/
│   │   │   ├── index.ts
│   │   │   ├── scans.ts
│   │   │   ├── findings.ts
│   │   │   └── metrics.ts
│   │   ├── types/
│   │   │   ├── api.ts
│   │   │   ├── scans.ts
│   │   │   └── findings.ts
│   │   ├── utils/
│   │   │   ├── formatters.ts
│   │   │   └── validators.ts
│   │   └── assets/
│   │       ├── styles/
│   │       └── images/
│   └── public/
│       ├── index.html
│       └── favicon.ico
├── migrations/
│   ├── alembic.ini
│   ├── env.py
│   └── versions/
└── monitoring/
    ├── prometheus/
    ├── grafana/
    └── alerts/
```

## Key Files and Their Purpose

### Core Configuration Files

#### `requirements.txt`
```txt
fastapi==0.104.1
uvicorn==0.24.0
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.8
redis==5.0.1
celery==5.3.4
pydantic==2.5.0
pydantic-settings==2.1.0
requests==2.31.0
aiohttp==3.9.1
PyYAML==6.0.1
click==8.1.7
rich==13.7.0
typer==0.9.0
semgrep==1.45.0
bandit==1.7.5
safety==2.3.5
trufflesecurity/trufflehog3==3.63.2
gitpython==3.1.40
openai==1.3.7
langchain==0.0.340
```

#### `docker-compose.yml`
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: devsecure
      POSTGRES_USER: devsecure
      POSTGRES_PASSWORD: devsecure
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://devsecure:devsecure@postgres:5432/devsecure
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - ./devsecure:/app/devsecure
      - ./config:/app/config

  worker:
    build: .
    command: celery -A devsecure.workers worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://devsecure:devsecure@postgres:5432/devsecure
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - ./devsecure:/app/devsecure

  dashboard:
    build: ./dashboard
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    volumes:
      - ./dashboard/src:/app/src

volumes:
  postgres_data:
  redis_data:
```

#### `.env.example`
```env
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/devsecure
REDIS_URL=redis://localhost:6379/0

# GitHub Integration
GITHUB_TOKEN=ghp_your_token_here
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# AI Integration
OPENAI_API_KEY=sk-your-key-here
AI_MODEL=gpt-4

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
ENVIRONMENT=development

# External Services
SECURITY_SCORECARD_API_KEY=your-key-here
NVD_API_KEY=your-nvd-key-here
```

### Core Implementation Files

#### `devsecure/core/models.py`
```python
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum
import uuid

Base = declarative_base()

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    branch = Column(String, default="main")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="repository")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    status = Column(String, default=ScanStatus.PENDING)
    domains = Column(JSON)  # List of domains to scan
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    config = Column(JSON)
    
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"))
    type = Column(String, nullable=False)  # SQL_INJECTION, XSS, etc.
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    file_path = Column(String)
    line_number = Column(Integer)
    column_number = Column(Integer)
    code_snippet = Column(Text)
    fix_available = Column(Boolean, default=False)
    fix_confidence = Column(String)
    metadata = Column(JSON)
    
    scan = relationship("Scan", back_populates="findings")
    fix = relationship("Fix", back_populates="finding", uselist=False)

class Fix(Base):
    __tablename__ = "fixes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String, ForeignKey("findings.id"))
    original_code = Column(Text)
    fixed_code = Column(Text)
    explanation = Column(Text)
    confidence = Column(String)
    pr_url = Column(String)
    applied = Column(Boolean, default=False)
    success = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    finding = relationship("Finding", back_populates="fix")
```

#### `devsecure/analyzers/base.py`
```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path
from ..core.models import Finding

class BaseAnalyzer(ABC):
    """Base class for all security analyzers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
    
    @abstractmethod
    def analyze(self, repository_path: Path) -> List[Finding]:
        """Analyze repository and return findings"""
        pass
    
    @abstractmethod
    def get_supported_languages(self) -> List[str]:
        """Return list of supported programming languages"""
        pass
    
    @abstractmethod
    def get_vulnerability_types(self) -> List[str]:
        """Return list of vulnerability types this analyzer can detect"""
        pass
    
    def is_file_supported(self, file_path: Path) -> bool:
        """Check if file type is supported by this analyzer"""
        return file_path.suffix in self.get_supported_extensions()
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """Return list of supported file extensions"""
        pass
```

#### `devsecure/analyzers/sast/analyzer.py`
```python
from typing import List, Dict, Any
from pathlib import Path
import subprocess
import json
import re

from ..base import BaseAnalyzer
from ...core.models import Finding, SeverityLevel

class SastAnalyzer(BaseAnalyzer):
    """Static Application Security Testing analyzer"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.semgrep_rules = config.get('semgrep_rules', 'auto')
        self.custom_rules = config.get('custom_rules', [])
    
    def analyze(self, repository_path: Path) -> List[Finding]:
        """Run SAST analysis using Semgrep and custom rules"""
        findings = []
        
        # Run Semgrep
        semgrep_findings = self._run_semgrep(repository_path)
        findings.extend(semgrep_findings)
        
        # Run custom pattern matching
        custom_findings = self._run_custom_rules(repository_path)
        findings.extend(custom_findings)
        
        return findings
    
    def _run_semgrep(self, repo_path: Path) -> List[Finding]:
        """Execute Semgrep analysis"""
        cmd = [
            'semgrep',
            '--config', self.semgrep_rules,
            '--json',
            '--no-git-ignore',
            str(repo_path)
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            semgrep_output = json.loads(result.stdout)
            
            findings = []
            for result in semgrep_output.get('results', []):
                finding = self._create_finding_from_semgrep(result)
                if finding:
                    findings.append(finding)
            
            return findings
        
        except subprocess.CalledProcessError as e:
            print(f"Semgrep failed: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"Failed to parse Semgrep output: {e}")
            return []
    
    def _create_finding_from_semgrep(self, result: Dict) -> Finding:
        """Convert Semgrep result to Finding object"""
        return Finding(
            type=result['check_id'].upper().replace('.', '_'),
            severity=self._map_severity(result.get('extra', {}).get('severity', 'medium')),
            title=result['extra']['message'],
            description=result['extra'].get('metadata', {}).get('description', ''),
            file_path=result['path'],
            line_number=result['start']['line'],
            column_number=result['start']['col'],
            code_snippet=self._extract_code_snippet(result),
            fix_available=self._can_auto_fix(result['check_id']),
            metadata={
                'semgrep_rule': result['check_id'],
                'confidence': result['extra'].get('metadata', {}).get('confidence', 'medium')
            }
        )
    
    def _map_severity(self, semgrep_severity: str) -> str:
        """Map Semgrep severity to our severity levels"""
        mapping = {
            'ERROR': SeverityLevel.HIGH,
            'WARNING': SeverityLevel.MEDIUM,
            'INFO': SeverityLevel.LOW
        }
        return mapping.get(semgrep_severity.upper(), SeverityLevel.MEDIUM)
    
    def _can_auto_fix(self, rule_id: str) -> bool:
        """Determine if finding can be auto-fixed"""
        fixable_patterns = [
            'sql-injection',
            'xss',
            'hardcoded-secret',
            'weak-crypto',
            'path-traversal'
        ]
        return any(pattern in rule_id.lower() for pattern in fixable_patterns)
    
    def get_supported_languages(self) -> List[str]:
        return ['python', 'javascript', 'typescript', 'java', 'go', 'php', 'ruby', 'c', 'cpp']
    
    def get_supported_extensions(self) -> List[str]:
        return ['.py', '.js', '.ts', '.java', '.go', '.php', '.rb', '.c', '.cpp', '.h']
    
    def get_vulnerability_types(self) -> List[str]:
        return [
            'SQL_INJECTION',
            'XSS',
            'COMMAND_INJECTION',
            'PATH_TRAVERSAL',
            'HARDCODED_SECRET',
            'WEAK_CRYPTO',
            'INSECURE_DESERIALIZATION'
        ]
```

### Implementation Phases Detail

#### Phase 1: Foundation (Week 1-4)
```python
# Week 1: Project Setup
- Set up project structure
- Configure development environment
- Database schema design
- Basic CLI framework

# Week 2: Core SAST
- Implement SastAnalyzer with Semgrep integration
- Basic finding model and storage
- Simple pattern matching for Python

# Week 3: Web API
- FastAPI setup with basic endpoints
- Database integration with SQLAlchemy
- Authentication and authorization

# Week 4: Basic Dashboard
- React setup with TypeScript
- Basic findings display
- Real-time updates with WebSocket
```

#### Phase 2: Multi-Domain (Week 5-8)
```python
# Week 5: SCA Implementation
- Package manager parsers (npm, pip)
- Vulnerability database integration
- Dependency graph analysis

# Week 6: Secrets Detection
- Entropy-based detection
- Pattern matching for common secret types
- Git history scanning

# Week 7: IaC Security
- Terraform parser and analyzer
- Security rule engine
- Compliance framework mapping

# Week 8: Container Security
- Dockerfile analysis
- Image vulnerability scanning
- Integration with Trivy/Clair
```
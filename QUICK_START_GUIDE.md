# DevSecure Quick Start Guide

## Overview

This guide will get you up and running with DevSecure development in 30 minutes. Follow these steps to set up your development environment and start building the unified security platform.

## Prerequisites

- **Python 3.9+** installed
- **Node.js 16+** and npm
- **Docker** and Docker Compose
- **Git** configured with GitHub access
- **PostgreSQL 13+** (or use Docker)
- **Redis 6+** (or use Docker)

## 🚀 Quick Setup (5 minutes)

### 1. Clone and Setup Project
```bash
# Create new project
mkdir devsecure && cd devsecure
git init

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install core dependencies
pip install fastapi uvicorn sqlalchemy psycopg2-binary redis celery
pip install pytest black mypy pre-commit semgrep
```

### 2. Project Structure Setup
```bash
# Create core directory structure
mkdir -p {devsecure/{core,analyzers,autofix,api,workers,cli},tests/{unit,integration,e2e},config,scripts}

# Create basic files
touch devsecure/__init__.py
touch devsecure/core/{__init__.py,models.py,database.py}
touch devsecure/analyzers/{__init__.py,base.py}
touch requirements.txt requirements-dev.txt
```

### 3. Database Setup with Docker
```bash
# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
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
  postgres_data:
EOF

# Start services
docker-compose up -d

# Verify services are running
docker-compose ps
```

## 💻 Core Implementation (20 minutes)

### 1. Create Core Models (5 minutes)
```bash
# Create devsecure/core/models.py
cat > devsecure/core/models.py << 'EOF'
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

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="repository")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    status = Column(String, default="pending")
    domains = Column(JSON)
    started_at = Column(DateTime, default=datetime.utcnow)
    
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"))
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    file_path = Column(String)
    line_number = Column(Integer)
    fix_available = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="findings")
EOF
```

### 2. Create Database Connection (3 minutes)
```bash
# Create devsecure/core/database.py
cat > devsecure/core/database.py << 'EOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://devsecure:devsecure@localhost:5432/devsecure")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOF
```

### 3. Create Basic SAST Analyzer (7 minutes)
```bash
# Create devsecure/analyzers/base.py
cat > devsecure/analyzers/base.py << 'EOF'
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path
from ..core.models import Finding

class BaseAnalyzer(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    @abstractmethod
    def analyze(self, repository_path: Path) -> List[Finding]:
        pass
    
    @abstractmethod
    def get_supported_languages(self) -> List[str]:
        pass
EOF

# Create devsecure/analyzers/sast_analyzer.py
cat > devsecure/analyzers/sast_analyzer.py << 'EOF'
from typing import List, Dict, Any
from pathlib import Path
import subprocess
import json
import re

from .base import BaseAnalyzer
from ..core.models import Finding

class SastAnalyzer(BaseAnalyzer):
    def analyze(self, repository_path: Path) -> List[Finding]:
        findings = []
        
        # Simple pattern-based detection for demo
        python_files = list(repository_path.glob("**/*.py"))
        
        for file_path in python_files:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                findings.extend(self._check_sql_injection(file_path, content))
                findings.extend(self._check_xss(file_path, content))
        
        return findings
    
    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        # Look for f-string SQL queries (basic pattern)
        pattern = r'\.execute\(f["\'].*\{.*\}.*["\']'
        
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                findings.append(Finding(
                    type="SQL_INJECTION",
                    severity="high",
                    title="Potential SQL Injection",
                    file_path=str(file_path),
                    line_number=i,
                    fix_available=True
                ))
        
        return findings
    
    def _check_xss(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        # Look for unescaped HTML output
        pattern = r'f["\']<.*\{.*\}.*>["\']'
        
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                findings.append(Finding(
                    type="XSS",
                    severity="medium", 
                    title="Potential Cross-Site Scripting",
                    file_path=str(file_path),
                    line_number=i,
                    fix_available=True
                ))
        
        return findings
    
    def get_supported_languages(self) -> List[str]:
        return ["python"]
EOF
```

### 4. Create Basic API (5 minutes)
```bash
# Create devsecure/api/main.py
cat > devsecure/api/main.py << 'EOF'
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
import uuid

from ..core.database import get_db, create_tables
from ..core.models import Repository, Scan, Finding
from ..analyzers.sast_analyzer import SastAnalyzer
from pathlib import Path

app = FastAPI(title="DevSecure API", version="1.0.0")

# Create tables on startup
create_tables()

class ScanRequest(BaseModel):
    repository_path: str
    domains: List[str] = ["sast"]

class ScanResponse(BaseModel):
    id: str
    status: str
    repository_path: str
    domains: List[str]

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    # Create scan record
    scan = Scan(
        id=str(uuid.uuid4()),
        status="pending",
        domains=request.domains
    )
    db.add(scan)
    db.commit()
    
    # Run analysis (simplified for demo)
    if "sast" in request.domains:
        analyzer = SastAnalyzer({})
        repo_path = Path(request.repository_path)
        
        if repo_path.exists():
            findings = analyzer.analyze(repo_path)
            
            for finding in findings:
                finding.scan_id = scan.id
                db.add(finding)
            
            scan.status = "completed"
        else:
            scan.status = "failed"
        
        db.commit()
    
    return ScanResponse(
        id=scan.id,
        status=scan.status,
        repository_path=request.repository_path,
        domains=scan.domains
    )

@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "id": scan.id,
        "status": scan.status,
        "domains": scan.domains,
        "findings_count": len(scan.findings)
    }

@app.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    return [{
        "id": f.id,
        "type": f.type,
        "severity": f.severity,
        "title": f.title,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "fix_available": f.fix_available
    } for f in findings]
EOF
```

## 🧪 Testing Setup (5 minutes)

### 1. Create Test Structure
```bash
# Create basic test
cat > tests/test_basic.py << 'EOF'
import pytest
from pathlib import Path
from devsecure.analyzers.sast_analyzer import SastAnalyzer
from devsecure.core.models import SeverityLevel

def test_sast_analyzer_sql_injection(tmp_path):
    # Create test file with SQL injection
    test_file = tmp_path / "test.py"
    test_file.write_text('''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
    ''')
    
    analyzer = SastAnalyzer({})
    findings = analyzer.analyze(tmp_path)
    
    assert len(findings) > 0
    sql_findings = [f for f in findings if f.type == "SQL_INJECTION"]
    assert len(sql_findings) >= 1

def test_api_health():
    from devsecure.api.main import app
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
EOF

# Create requirements files
cat > requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.8
redis==5.0.1
celery==5.3.4
pydantic==2.5.0
requests==2.31.0
EOF

cat > requirements-dev.txt << 'EOF'
-r requirements.txt
pytest==7.4.3
pytest-cov==4.1.0
black==23.10.1
mypy==1.7.0
pre-commit==3.5.0
httpx==0.25.2
EOF

# Install dev dependencies
pip install -r requirements-dev.txt
```

### 2. Run Initial Tests
```bash
# Run tests
pytest tests/test_basic.py -v

# Expected output:
# tests/test_basic.py::test_sast_analyzer_sql_injection PASSED
# tests/test_basic.py::test_api_health PASSED
```

## 🌐 Basic Web Interface (Optional - 10 minutes)

### 1. Create Simple Frontend
```bash
# Create dashboard directory
mkdir dashboard && cd dashboard

# Initialize React app (if Node.js available)
npx create-react-app . --template typescript
npm install axios

# Or create simple HTML dashboard
mkdir -p static/js static/css templates

cat > templates/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>DevSecure Dashboard</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .scan { border: 1px solid #ddd; padding: 20px; margin: 10px 0; }
        .finding { background: #f9f9f9; padding: 10px; margin: 5px 0; }
        .high { border-left: 4px solid #ff4444; }
        .medium { border-left: 4px solid #ffaa00; }
    </style>
</head>
<body>
    <h1>DevSecure Dashboard</h1>
    
    <h2>Start New Scan</h2>
    <form id="scanForm">
        <input type="text" id="repoPath" placeholder="Repository path" style="width: 300px;">
        <button type="submit">Start Scan</button>
    </form>
    
    <h2>Recent Scans</h2>
    <div id="scans"></div>
    
    <script>
        const API_BASE = 'http://localhost:8000';
        
        document.getElementById('scanForm').onsubmit = async (e) => {
            e.preventDefault();
            const repoPath = document.getElementById('repoPath').value;
            
            const response = await fetch(`${API_BASE}/scans`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({repository_path: repoPath, domains: ['sast']})
            });
            
            if (response.ok) {
                const scan = await response.json();
                alert(`Scan started: ${scan.id}`);
                loadScans();
            }
        };
        
        async function loadScans() {
            // This would load recent scans in a real implementation
            document.getElementById('scans').innerHTML = '<p>Scans will be displayed here</p>';
        }
        
        loadScans();
    </script>
</body>
</html>
EOF

cd ..
```

## 🚀 Run the Application

### 1. Start the API Server
```bash
# Terminal 1: Start API
cd devsecure
export DATABASE_URL="postgresql://devsecure:devsecure@localhost:5432/devsecure"
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# API will be available at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### 2. Test the API
```bash
# Terminal 2: Test the API
# Check health
curl http://localhost:8000/health

# Create a test scan (replace path with actual repository)
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "/path/to/your/repo", "domains": ["sast"]}'

# Get scan results (use scan ID from previous response)
curl http://localhost:8000/scans/your-scan-id/findings
```

### 3. Create Test Repository
```bash
# Create a test repository with vulnerabilities
mkdir test-repo && cd test-repo

cat > vulnerable_app.py << 'EOF'
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# XSS vulnerability
@app.route('/welcome')
def welcome():
    name = request.args.get('name', '')
    return f"<h1>Welcome {name}!</h1>"

if __name__ == '__main__':
    app.run(debug=True)
EOF

cd ..

# Now scan it
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "./test-repo", "domains": ["sast"]}'
```

## 📋 Next Steps

### Immediate Tasks (Next 1-2 hours)
1. **Add more analyzers**: SCA, Secrets detection
2. **Improve SAST patterns**: Add more vulnerability types
3. **Basic auto-fix**: Implement simple pattern-based fixes
4. **Better error handling**: Add proper exception handling
5. **Logging**: Add comprehensive logging

### Short-term Goals (Next 1-2 weeks)
1. **Database migrations**: Add Alembic for schema management
2. **Authentication**: Add JWT-based authentication
3. **GitHub integration**: Basic PR creation
4. **Web dashboard**: React-based interface
5. **Testing**: Comprehensive test suite

### Medium-term Goals (Next 1-2 months)
1. **AI integration**: OpenAI-based auto-fixing
2. **Performance optimization**: Async processing, caching
3. **Container security**: Docker/Kubernetes scanning
4. **Correlation engine**: Cross-domain vulnerability relationships
5. **Production deployment**: Docker, Kubernetes, monitoring

## 🛠 Development Workflow

### Daily Development
```bash
# Activate environment
source venv/bin/activate

# Start services
docker-compose up -d

# Run tests
pytest tests/ -v

# Start development server
uvicorn devsecure.api.main:app --reload

# Code formatting
black devsecure/
mypy devsecure/
```

### Before Committing
```bash
# Run full test suite
pytest tests/ --cov=devsecure

# Check code quality
black --check devsecure/
mypy devsecure/

# Security scan
bandit -r devsecure/
```

## 🔧 Troubleshooting

### Common Issues

1. **Database Connection Error**
   ```bash
   # Check if PostgreSQL is running
   docker-compose ps
   
   # Restart services
   docker-compose down && docker-compose up -d
   ```

2. **Import Errors**
   ```bash
   # Make sure you're in the right directory and venv is activated
   pwd  # Should be in devsecure/
   which python  # Should point to venv
   
   # Install missing dependencies
   pip install -r requirements-dev.txt
   ```

3. **Test Failures**
   ```bash
   # Check test dependencies
   pip install pytest pytest-cov
   
   # Run specific test
   pytest tests/test_basic.py::test_sast_analyzer_sql_injection -v -s
   ```

## 📚 Resources

### Documentation
- **FastAPI**: https://fastapi.tiangolo.com/
- **SQLAlchemy**: https://docs.sqlalchemy.org/
- **Pytest**: https://docs.pytest.org/
- **Semgrep**: https://semgrep.dev/docs/

### Security Resources
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Database**: https://cwe.mitre.org/
- **NIST Cybersecurity**: https://www.nist.gov/cybersecurity

### Example Repositories
- **Vulnerable Code Samples**: https://github.com/OWASP/WebGoat
- **Security Testing**: https://github.com/securecodewarrior/
- **SAST Tools**: https://github.com/analysis-tools-dev/static-analysis

## 🎯 Success Metrics

After completing this guide, you should be able to:

✅ **Scan a repository** and find basic vulnerabilities  
✅ **API endpoints** working and documented  
✅ **Database** storing scan results  
✅ **Tests passing** with basic coverage  
✅ **Development environment** fully functional  

You now have a foundation to build upon. Follow the detailed requirements and implementation roadmap documents to continue developing the full DevSecure platform.

**Happy coding! 🚀**
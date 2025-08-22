# DevSecure Testing Strategy

## Overview

This document outlines a comprehensive testing strategy for the DevSecure platform, ensuring reliability, accuracy, and performance at production scale.

## Testing Pyramid Structure

```
                    /\
                   /  \
                  / E2E \
                 /______\
                /        \
               /Integration\
              /____________\
             /              \
            /      Unit      \
           /__________________\
```

## 1. Unit Testing (70% of tests)

### 1.1 Core Components Testing

#### Analyzers Testing
```python
# tests/unit/analyzers/test_sast_analyzer.py
import pytest
from pathlib import Path
from devsecure.analyzers.sast.analyzer import SastAnalyzer
from devsecure.core.models import Finding, SeverityLevel

class TestSastAnalyzer:
    
    @pytest.fixture
    def analyzer(self):
        config = {"semgrep_rules": "auto", "custom_rules": []}
        return SastAnalyzer(config)
    
    @pytest.fixture
    def vulnerable_python_code(self):
        return '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
        '''
    
    def test_detect_sql_injection(self, analyzer, vulnerable_python_code, tmp_path):
        # Create temporary Python file
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text(vulnerable_python_code)
        
        # Run analysis
        findings = analyzer.analyze(tmp_path)
        
        # Assertions
        assert len(findings) > 0
        sql_injection_findings = [f for f in findings if 'sql' in f.type.lower()]
        assert len(sql_injection_findings) >= 1
        
        finding = sql_injection_findings[0]
        assert finding.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert "sql" in finding.type.lower()
        assert finding.file_path == str(test_file)
        assert finding.line_number > 0
    
    def test_supported_languages(self, analyzer):
        languages = analyzer.get_supported_languages()
        expected = ['python', 'javascript', 'typescript', 'java', 'go']
        for lang in expected:
            assert lang in languages
    
    def test_vulnerability_types(self, analyzer):
        vuln_types = analyzer.get_vulnerability_types()
        expected = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION']
        for vuln_type in expected:
            assert vuln_type in vuln_types

# tests/unit/analyzers/test_sca_analyzer.py
class TestScaAnalyzer:
    
    @pytest.fixture
    def analyzer(self):
        return ScaAnalyzer({})
    
    def test_parse_package_json(self, analyzer, tmp_path):
        package_json = {
            "dependencies": {
                "express": "4.17.1",
                "lodash": "4.17.20"
            },
            "devDependencies": {
                "jest": "26.6.3"
            }
        }
        
        file_path = tmp_path / "package.json"
        file_path.write_text(json.dumps(package_json))
        
        dependencies = analyzer.parse_package_json(file_path)
        
        assert len(dependencies) == 2  # Only production dependencies
        assert any(d.name == "express" and d.version == "4.17.1" for d in dependencies)
        assert any(d.name == "lodash" and d.version == "4.17.20" for d in dependencies)
```

#### Auto-Fix Engine Testing
```python
# tests/unit/autofix/test_fix_patterns.py
class TestFixPatterns:
    
    @pytest.fixture
    def sql_injection_pattern(self):
        return FixPattern(
            name="sql_injection_format",
            pattern=r'cursor\.execute\(f"([^"]*\{[^}]*\}[^"]*)"',
            replacement=r'cursor.execute("$1", params)',
            confidence=FixConfidence.HIGH
        )
    
    def test_sql_injection_fix(self, sql_injection_pattern):
        vulnerable_code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        '''
        
        context = CodeContext(
            file_path="test.py",
            function_name="get_user",
            imports=["sqlite3"],
            variables={"user_id": "int"}
        )
        
        result = sql_injection_pattern.apply(vulnerable_code, context)
        
        assert result.success
        assert "cursor.execute(" in result.fixed_code
        assert ", params)" in result.fixed_code
        assert "{user_id}" not in result.fixed_code
        assert result.confidence == FixConfidence.HIGH

# tests/unit/autofix/test_ai_codegen.py
class TestAICodeGenerator:
    
    @pytest.mark.asyncio
    async def test_generate_sql_injection_fix(self, mock_openai_client):
        generator = AICodeGenerator("test-api-key")
        
        finding = Finding(
            type="SQL_INJECTION",
            severity=SeverityLevel.HIGH,
            file_path="app.py",
            line_number=15,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        )
        
        context = CodeContext(
            file_path="app.py",
            function_name="get_user",
            surrounding_code="def get_user(user_id):\n    conn = sqlite3.connect('db')\n    cursor = conn.cursor()",
            imports=["sqlite3"]
        )
        
        # Mock OpenAI response
        mock_openai_client.chat.completions.create.return_value.choices[0].message.content = \
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        
        fix = await generator.generate_fix(finding, context)
        
        assert "cursor.execute(" in fix
        assert "?" in fix  # Parameterized query
        assert "(user_id,)" in fix  # Parameter tuple
```

### 1.2 Database Model Testing
```python
# tests/unit/core/test_models.py
class TestModels:
    
    def test_repository_creation(self, db_session):
        repo = Repository(
            name="test-repo",
            url="https://github.com/user/test-repo",
            branch="main"
        )
        db_session.add(repo)
        db_session.commit()
        
        assert repo.id is not None
        assert repo.created_at is not None
        assert repo.updated_at is not None
    
    def test_scan_finding_relationship(self, db_session):
        repo = Repository(name="test", url="https://github.com/test/test")
        scan = Scan(repository=repo, domains=["sast"])
        finding = Finding(
            scan=scan,
            type="SQL_INJECTION",
            severity=SeverityLevel.HIGH,
            title="SQL Injection found"
        )
        
        db_session.add_all([repo, scan, finding])
        db_session.commit()
        
        assert scan.id is not None
        assert finding.scan_id == scan.id
        assert len(scan.findings) == 1
        assert scan.findings[0] == finding
```

### 1.3 API Logic Testing
```python
# tests/unit/api/test_scans.py
class TestScansAPI:
    
    @pytest.mark.asyncio
    async def test_create_scan(self, client, mock_scan_service):
        scan_request = {
            "repository_url": "https://github.com/user/repo",
            "domains": ["sast", "sca"],
            "auto_fix": True
        }
        
        mock_scan_service.create_scan.return_value = Scan(
            id="test-scan-123",
            status=ScanStatus.PENDING,
            domains=["sast", "sca"]
        )
        
        response = await client.post("/api/scans", json=scan_request)
        
        assert response.status_code == 201
        data = response.json()
        assert data["id"] == "test-scan-123"
        assert data["status"] == "pending"
        assert data["domains"] == ["sast", "sca"]
```

## 2. Integration Testing (20% of tests)

### 2.1 Database Integration
```python
# tests/integration/test_database.py
class TestDatabaseIntegration:
    
    def test_scan_workflow_integration(self, db_session):
        # Create repository
        repo = Repository(name="integration-test", url="https://github.com/test/repo")
        db_session.add(repo)
        db_session.flush()
        
        # Create scan
        scan = Scan(repository_id=repo.id, domains=["sast"])
        db_session.add(scan)
        db_session.flush()
        
        # Add findings
        findings = [
            Finding(scan_id=scan.id, type="SQL_INJECTION", severity="high"),
            Finding(scan_id=scan.id, type="XSS", severity="medium")
        ]
        db_session.add_all(findings)
        db_session.commit()
        
        # Query and verify
        retrieved_scan = db_session.query(Scan).filter_by(id=scan.id).first()
        assert retrieved_scan is not None
        assert len(retrieved_scan.findings) == 2
        assert retrieved_scan.repository.name == "integration-test"
```

### 2.2 External Service Integration
```python
# tests/integration/test_github_integration.py
class TestGitHubIntegration:
    
    @pytest.mark.integration
    def test_create_real_pull_request(self, github_client, test_repository):
        # Use a real test repository for integration testing
        fixes = [
            Fix(
                file_path="src/app.py",
                original_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                fixed_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                explanation="Fixed SQL injection vulnerability using parameterized query"
            )
        ]
        
        pr = github_client.create_pull_request(
            repository=test_repository,
            title="Security Fix: SQL Injection Vulnerability",
            fixes=fixes,
            base_branch="main"
        )
        
        assert pr.number > 0
        assert pr.state == "open"
        assert "SQL Injection" in pr.title
        
        # Clean up - close the test PR
        github_client.close_pull_request(test_repository, pr.number)

# tests/integration/test_semgrep_integration.py
class TestSemgrepIntegration:
    
    @pytest.mark.integration
    def test_semgrep_analysis(self, tmp_path):
        # Create test repository with known vulnerabilities
        vulnerable_file = tmp_path / "app.py"
        vulnerable_file.write_text('''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    cursor.execute(query)
    return cursor.fetchone()

def render_template(user_input):
    return f"<html><body>{user_input}</body></html>"  # XSS
        ''')
        
        analyzer = SastAnalyzer({"semgrep_rules": "auto"})
        findings = analyzer.analyze(tmp_path)
        
        # Should find both SQL injection and XSS
        assert len(findings) >= 2
        
        finding_types = [f.type.lower() for f in findings]
        assert any("sql" in t for t in finding_types)
        assert any("xss" in t or "injection" in t for t in finding_types)
```

### 2.3 API Integration Testing
```python
# tests/integration/test_api_integration.py
class TestAPIIntegration:
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, client, test_repository_path):
        # Start scan
        scan_request = {
            "repository_path": str(test_repository_path),
            "domains": ["sast"],
            "auto_fix": False
        }
        
        response = await client.post("/api/scans", json=scan_request)
        assert response.status_code == 201
        scan_data = response.json()
        scan_id = scan_data["id"]
        
        # Wait for scan completion (with timeout)
        max_wait = 30  # seconds
        waited = 0
        while waited < max_wait:
            response = await client.get(f"/api/scans/{scan_id}")
            scan_status = response.json()["status"]
            
            if scan_status == "completed":
                break
            elif scan_status == "failed":
                pytest.fail("Scan failed")
            
            await asyncio.sleep(1)
            waited += 1
        
        assert scan_status == "completed"
        
        # Get findings
        response = await client.get(f"/api/scans/{scan_id}/findings")
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) > 0
```

## 3. End-to-End Testing (10% of tests)

### 3.1 Complete User Workflows
```python
# tests/e2e/test_complete_workflows.py
class TestCompleteWorkflows:
    
    @pytest.mark.e2e
    async def test_scan_and_autofix_workflow(self, browser, base_url):
        page = await browser.new_page()
        
        # Navigate to dashboard
        await page.goto(f"{base_url}/dashboard")
        
        # Start new scan
        await page.click("button:has-text('New Scan')")
        await page.fill("input[name='repository_url']", "https://github.com/test/vulnerable-repo")
        await page.check("input[value='sast']")
        await page.check("input[value='auto_fix']")
        await page.click("button:has-text('Start Scan')")
        
        # Wait for scan completion
        await page.wait_for_selector("text=Scan Completed", timeout=60000)
        
        # Verify findings are displayed
        findings_count = await page.locator(".finding-row").count()
        assert findings_count > 0
        
        # Check auto-fix results
        await page.click("text=Auto-Fix Results")
        pr_links = await page.locator("a:has-text('Pull Request')").count()
        assert pr_links > 0
    
    @pytest.mark.e2e
    async def test_vulnerability_correlation(self, browser, base_url):
        page = await browser.new_page()
        await page.goto(f"{base_url}/correlation")
        
        # Wait for correlation graph to load
        await page.wait_for_selector("svg.correlation-graph")
        
        # Verify graph elements
        nodes = await page.locator("circle.node").count()
        edges = await page.locator("line.edge").count()
        
        assert nodes > 0
        assert edges > 0
        
        # Test filtering
        await page.select_option("select[name='severity']", "critical")
        await page.wait_for_load_state("networkidle")
        
        # Verify filtering worked
        critical_nodes = await page.locator("circle.node.critical").count()
        assert critical_nodes > 0
```

### 3.2 Performance Testing
```python
# tests/e2e/test_performance.py
class TestPerformance:
    
    @pytest.mark.performance
    async def test_large_repository_scan(self, client):
        # Test with a large repository (10k+ LOC)
        large_repo_request = {
            "repository_url": "https://github.com/large/repository",
            "domains": ["sast", "sca", "secrets"]
        }
        
        start_time = time.time()
        
        response = await client.post("/api/scans", json=large_repo_request)
        scan_id = response.json()["id"]
        
        # Wait for completion and measure time
        while True:
            response = await client.get(f"/api/scans/{scan_id}")
            status = response.json()["status"]
            
            if status == "completed":
                break
            elif status == "failed":
                pytest.fail("Large repository scan failed")
            
            await asyncio.sleep(5)
        
        total_time = time.time() - start_time
        
        # Should complete within reasonable time (adjust based on requirements)
        assert total_time < 600  # 10 minutes max
        
        # Get performance metrics
        response = await client.get(f"/api/scans/{scan_id}/metrics")
        metrics = response.json()
        
        # Verify performance targets
        assert metrics["lines_of_code"] > 10000
        assert metrics["scan_rate_loc_per_second"] > 100
        assert metrics["memory_usage_mb"] < 2000
    
    @pytest.mark.performance
    async def test_concurrent_scans(self, client):
        # Test multiple concurrent scans
        scan_requests = [
            {"repository_url": f"https://github.com/test/repo{i}", "domains": ["sast"]}
            for i in range(10)
        ]
        
        # Start all scans concurrently
        tasks = [client.post("/api/scans", json=req) for req in scan_requests]
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 201
        
        # Monitor system resources
        # This would require additional monitoring setup
        pass
```

## 4. Test Data Management

### 4.1 Test Repositories
```python
# tests/fixtures/repositories.py
@pytest.fixture
def vulnerable_python_repo(tmp_path):
    """Create a test repository with known Python vulnerabilities"""
    repo_path = tmp_path / "vulnerable_python"
    repo_path.mkdir()
    
    # SQL Injection vulnerability
    (repo_path / "sql_injection.py").write_text('''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
    ''')
    
    # XSS vulnerability
    (repo_path / "xss.py").write_text('''
from flask import Flask, request

app = Flask(__name__)

@app.route('/welcome')
def welcome():
    name = request.args.get('name', '')
    return f"<h1>Welcome {name}!</h1>"
    ''')
    
    # Hardcoded secret
    (repo_path / "secrets.py").write_text('''
import requests

API_KEY = "sk-1234567890abcdef1234567890abcdef"

def call_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)
    ''')
    
    return repo_path

@pytest.fixture
def vulnerable_javascript_repo(tmp_path):
    """Create a test repository with known JavaScript vulnerabilities"""
    repo_path = tmp_path / "vulnerable_js"
    repo_path.mkdir()
    
    # Command injection
    (repo_path / "command_injection.js").write_text('''
const { exec } = require('child_process');

function processFile(filename) {
    exec(`cat ${filename}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}
    ''')
    
    # Package.json with vulnerable dependencies
    (repo_path / "package.json").write_text('''
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.10",
    "request": "2.88.0"
  }
}
    ''')
    
    return repo_path
```

### 4.2 Mock Data Factories
```python
# tests/fixtures/factories.py
class FindingFactory:
    @staticmethod
    def create_sql_injection_finding(**kwargs):
        defaults = {
            "type": "SQL_INJECTION",
            "severity": SeverityLevel.HIGH,
            "title": "SQL Injection vulnerability detected",
            "description": "User input is directly concatenated into SQL query",
            "file_path": "app.py",
            "line_number": 42,
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            "fix_available": True,
            "metadata": {
                "cwe": "CWE-89",
                "owasp": "A03:2021 – Injection"
            }
        }
        defaults.update(kwargs)
        return Finding(**defaults)
    
    @staticmethod
    def create_xss_finding(**kwargs):
        defaults = {
            "type": "XSS",
            "severity": SeverityLevel.MEDIUM,
            "title": "Cross-Site Scripting vulnerability",
            "description": "User input rendered without escaping",
            "file_path": "templates.py",
            "line_number": 15,
            "code_snippet": 'return f"<html>{user_input}</html>"',
            "fix_available": True
        }
        defaults.update(kwargs)
        return Finding(**defaults)
```

## 5. Test Environment Setup

### 5.1 Docker Test Environment
```yaml
# docker-compose.test.yml
version: '3.8'

services:
  test-db:
    image: postgres:15
    environment:
      POSTGRES_DB: devsecure_test
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
    ports:
      - "5433:5432"
    tmpfs:
      - /var/lib/postgresql/data

  test-redis:
    image: redis:7
    ports:
      - "6380:6379"
    tmpfs:
      - /data

  test-api:
    build: .
    environment:
      - DATABASE_URL=postgresql://test:test@test-db:5432/devsecure_test
      - REDIS_URL=redis://test-redis:6379/0
      - TESTING=true
    depends_on:
      - test-db
      - test-redis
    volumes:
      - ./tests:/app/tests
```

### 5.2 GitHub Actions CI/CD
```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt
          # Install security tools
          pip install semgrep bandit safety
      
      - name: Run unit tests
        run: |
          pytest tests/unit/ -v --cov=devsecure --cov-report=xml
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379/0
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Run integration tests
        run: |
          docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
          docker-compose -f docker-compose.test.yml down

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Playwright
        run: |
          npm install -g @playwright/test
          playwright install
      
      - name: Start application
        run: |
          docker-compose up -d
          # Wait for services to be ready
          sleep 30
      
      - name: Run E2E tests
        run: |
          playwright test tests/e2e/
      
      - name: Upload test artifacts
        uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: playwright-report
          path: playwright-report/
```

## 6. Quality Gates and Metrics

### 6.1 Code Coverage Requirements
- **Unit Tests**: Minimum 80% code coverage
- **Integration Tests**: Critical paths covered
- **E2E Tests**: Major user workflows covered

### 6.2 Performance Benchmarks
```python
# tests/benchmarks/performance_tests.py
class PerformanceBenchmarks:
    
    def test_scan_performance_targets(self):
        """Ensure scan performance meets targets"""
        test_cases = [
            {"loc": 1000, "max_time": 10},    # 1k LOC in 10 seconds
            {"loc": 10000, "max_time": 60},   # 10k LOC in 1 minute
            {"loc": 100000, "max_time": 600}, # 100k LOC in 10 minutes
        ]
        
        for case in test_cases:
            repo = create_test_repo(lines_of_code=case["loc"])
            
            start_time = time.time()
            findings = scan_repository(repo)
            scan_time = time.time() - start_time
            
            assert scan_time < case["max_time"], \
                f"Scan took {scan_time}s for {case['loc']} LOC, expected <{case['max_time']}s"
            
            # Verify scan rate
            scan_rate = case["loc"] / scan_time
            assert scan_rate > 100, f"Scan rate {scan_rate} LOC/s is below target of 100 LOC/s"
```

### 6.3 Security Testing
```python
# tests/security/test_security.py
class SecurityTests:
    
    def test_input_validation(self, client):
        """Test API input validation and sanitization"""
        malicious_inputs = [
            {"repository_url": "javascript:alert('xss')"},
            {"repository_url": "../../../etc/passwd"},
            {"repository_url": "'; DROP TABLE users; --"},
            {"domains": ["<script>alert('xss')</script>"]},
        ]
        
        for malicious_input in malicious_inputs:
            response = client.post("/api/scans", json=malicious_input)
            assert response.status_code in [400, 422], \
                f"Should reject malicious input: {malicious_input}"
    
    def test_authentication_required(self, client):
        """Ensure all protected endpoints require authentication"""
        protected_endpoints = [
            ("GET", "/api/scans"),
            ("POST", "/api/scans"),
            ("GET", "/api/findings"),
            ("POST", "/api/autofix"),
        ]
        
        for method, endpoint in protected_endpoints:
            response = client.request(method, endpoint)
            assert response.status_code == 401, \
                f"{method} {endpoint} should require authentication"
    
    def test_dependency_vulnerabilities(self):
        """Check for vulnerabilities in dependencies"""
        # Run safety check
        result = subprocess.run(["safety", "check", "--json"], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            vulnerabilities = json.loads(result.stdout)
            pytest.fail(f"Found {len(vulnerabilities)} dependency vulnerabilities")
```

## 7. Test Execution Strategy

### 7.1 Local Development
```bash
# Run quick tests during development
pytest tests/unit/ -x -v

# Run specific test file
pytest tests/unit/analyzers/test_sast_analyzer.py -v

# Run with coverage
pytest tests/unit/ --cov=devsecure --cov-report=html

# Run performance tests
pytest tests/benchmarks/ -m performance
```

### 7.2 CI/CD Pipeline
1. **Pre-commit hooks**: Linting, formatting, basic tests
2. **Pull Request**: Unit tests, integration tests, security scans
3. **Main branch**: Full test suite including E2E tests
4. **Release**: Performance tests, security audit, deployment tests

### 7.3 Production Monitoring
```python
# monitoring/health_checks.py
class ProductionHealthChecks:
    
    async def test_api_responsiveness(self):
        """Monitor API response times in production"""
        start_time = time.time()
        response = await httpx.get(f"{API_BASE_URL}/health")
        response_time = time.time() - start_time
        
        assert response.status_code == 200
        assert response_time < 1.0  # Should respond within 1 second
        
        return {
            "status": "healthy",
            "response_time": response_time,
            "timestamp": datetime.utcnow()
        }
    
    async def test_scan_accuracy(self):
        """Monitor scan accuracy with known vulnerable repositories"""
        test_repo = "https://github.com/devsecure/test-vulnerabilities"
        
        scan_request = {
            "repository_url": test_repo,
            "domains": ["sast"]
        }
        
        response = await httpx.post(f"{API_BASE_URL}/scans", json=scan_request)
        scan_id = response.json()["id"]
        
        # Wait for completion
        findings = await wait_for_scan_completion(scan_id)
        
        # Verify expected vulnerabilities are found
        expected_vulns = ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]
        found_vulns = [f["type"] for f in findings]
        
        for expected in expected_vulns:
            assert expected in found_vulns, f"Failed to detect {expected}"
        
        return {
            "status": "accurate",
            "expected_count": len(expected_vulns),
            "found_count": len(found_vulns),
            "accuracy": len(set(expected_vulns) & set(found_vulns)) / len(expected_vulns)
        }
```

## 8. Conclusion

This comprehensive testing strategy ensures the DevSecure platform is:

1. **Reliable**: Thorough unit and integration testing
2. **Accurate**: Real vulnerability detection validation
3. **Performant**: Performance benchmarks and load testing
4. **Secure**: Security testing and vulnerability scanning
5. **Maintainable**: Clear test structure and documentation

The key to success is implementing tests incrementally alongside development, maintaining high coverage, and continuously monitoring quality in production.

**Testing Checklist**:
- [ ] Unit tests for all core components (>80% coverage)
- [ ] Integration tests for external services
- [ ] E2E tests for critical user workflows
- [ ] Performance benchmarks and load testing
- [ ] Security testing and vulnerability scanning
- [ ] Production monitoring and health checks
- [ ] Automated CI/CD pipeline with quality gates
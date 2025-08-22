# DevSecure Usage Guide

## 🔍 How to Scan a Repository

DevSecure provides multiple ways to scan repositories for security vulnerabilities across all domains (SAST, SCA, Secrets, IaC, Container).

### Method 1: CLI Usage

#### Basic Repository Scan
```bash
# Scan current directory
python3 devsecure.py --scan-path . --output results.json

# Scan specific repository
python3 devsecure.py --scan-path /path/to/repo --output security-report.json

# Scan with auto-fix enabled
python3 devsecure.py --scan-path . --auto-fix --github-token YOUR_TOKEN
```

#### Advanced Scanning Options
```bash
# Full security scan with all domains
python3 devsecure.py \
  --scan-path ./my-project \
  --domains sast,sca,secrets,iac,container \
  --auto-fix \
  --pr-batch-size 5 \
  --github-token ghp_your_token_here \
  --output comprehensive-report.json

# Quick SAST-only scan
python3 devsecure.py \
  --scan-path . \
  --domains sast \
  --severity critical,high \
  --output sast-critical.json

# Container security scan
python3 devsecure.py \
  --scan-path . \
  --domains container \
  --dockerfile-path ./Dockerfile \
  --output container-security.json
```

#### Configuration File Usage
```bash
# Use custom configuration
python3 devsecure.py --config my-config.yaml --scan-path .

# Generate default configuration
python3 devsecure.py --generate-config
```

### Method 2: Web Dashboard Usage

1. **Access the Dashboard**: https://5000-igqpu3hgmlyvluq9smj6q-6532622b.e2b.dev

2. **Navigate to Scans**: Click "Scans" in the sidebar

3. **Create New Scan**:
   - Click "New Scan" button
   - Enter repository path or URL
   - Select security domains (SAST, SCA, Secrets, IaC, Container)
   - Configure auto-fix settings
   - Start scan

4. **Monitor Progress**: Real-time updates via WebSocket

5. **Review Results**: View findings in the dashboard with correlation analysis

### Method 3: API Usage

```bash
# Start a scan via API
curl -X POST "https://5000-igqpu3hgmlyvluq9smj6q-6532622b.e2b.dev/api/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path/to/repo",
    "domains": ["sast", "sca", "secrets"],
    "auto_fix": true,
    "github_token": "your_token"
  }'

# Get scan results
curl "https://5000-igqpu3hgmlyvluq9smj6q-6532622b.e2b.dev/api/findings"

# Get metrics
curl "https://5000-igqpu3hgmlyvluq9smj6q-6532622b.e2b.dev/api/metrics"
```

## 🛡️ Security Domains

### SAST (Static Code Analysis)
- **Languages**: Python, JavaScript, Java, C/C++, Go, Rust, etc.
- **Vulnerabilities**: SQL Injection, XSS, Command Injection, etc.
- **Auto-Fix**: 80%+ coverage with AI-generated patches

### SCA (Software Composition Analysis)  
- **Package Managers**: npm, pip, maven, gradle, cargo, etc.
- **Vulnerabilities**: Known CVEs in dependencies
- **Auto-Fix**: Version updates and patches

### Secrets Detection
- **Types**: API keys, passwords, certificates, tokens
- **Sources**: Code, config files, environment variables
- **Auto-Fix**: Replace with environment variables

### IaC (Infrastructure as Code)
- **Formats**: Terraform, CloudFormation, Kubernetes YAML
- **Issues**: Misconfigurations, security gaps
- **Auto-Fix**: Secure configuration updates

### Container Security
- **Images**: Docker, OCI containers
- **Vulnerabilities**: Base image CVEs, misconfigurations
- **Auto-Fix**: Base image updates, security hardening

## 📊 Output Formats

### JSON Report
```json
{
  "scan_id": "scan-2024-08-22-123456",
  "timestamp": "2024-08-22T02:30:00Z",
  "repository": "/path/to/repo",
  "summary": {
    "total_findings": 47,
    "critical": 8,
    "high": 12,
    "medium": 18,
    "low": 9,
    "auto_fixed": 23
  },
  "findings": [...],
  "correlation": {...},
  "recommendations": [...]
}
```

### Web Dashboard
- Real-time metrics and charts
- Interactive findings table
- Correlation visualization
- Auto-fix tracking
- PR management

## 🤖 Auto-Fix Features

### Smart PR Batching
- Groups fixes by severity and module
- Creates optimized pull requests
- Includes comprehensive testing

### Adaptive Quality
- Adjusts fix quality based on code criticality
- Higher confidence for critical systems
- Graduated rollout for safety

### Learning System
- Tracks fix effectiveness
- Improves over time
- Developer feedback integration

## ⚙️ Configuration

### config.yaml Example
```yaml
scan:
  domains:
    - sast
    - sca  
    - secrets
    - iac
    - container
  
  paths:
    include:
      - "src/**"
      - "lib/**"
    exclude:
      - "tests/**"
      - "node_modules/**"

auto_fix:
  enabled: true
  target_coverage: 0.8
  batch_size: 5
  confidence_threshold: 0.7

github:
  pr_title_template: "🔒 Security Fix: {vulnerability_type}"
  pr_description_template: "Automated security fix for {finding_count} findings"

correlation:
  enabled: true
  deduplicate: true
  cross_domain: true
```

## 🚀 Getting Started

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure GitHub Token**:
   ```bash
   export GITHUB_TOKEN=ghp_your_token_here
   ```

3. **Run Your First Scan**:
   ```bash
   python3 devsecure.py --scan-path . --auto-fix
   ```

4. **Access Web Dashboard**:
   Visit https://5000-igqpu3hgmlyvluq9smj6q-6532622b.e2b.dev

## 📈 Advanced Usage

### Continuous Integration
```yaml
# .github/workflows/devsecure.yml
name: DevSecure Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run DevSecure
        run: |
          python3 devsecure.py \
            --scan-path . \
            --auto-fix \
            --github-token ${{ secrets.GITHUB_TOKEN }}
```

### Custom Rules
```python
# custom_rules.py
from devsecure import CustomRule, Severity

class MyCustomRule(CustomRule):
    def pattern(self):
        return r"password\s*=\s*['\"][^'\"]+['\"]"
    
    def severity(self):
        return Severity.HIGH
    
    def message(self):
        return "Hardcoded password detected"
    
    def fix(self, match):
        return "password = os.getenv('PASSWORD')"
```

This comprehensive platform replaces traditional tools like Checkmarx One with a unified, AI-powered approach to application security.
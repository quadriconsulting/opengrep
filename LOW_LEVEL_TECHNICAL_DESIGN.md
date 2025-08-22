# DevSecure Low-Level Technical Design Document
## FastAPI + Supabase + Hetzner Infrastructure

### 📋 Document Overview

**Project**: DevSecure Unified Security Platform  
**Architecture**: FastAPI Backend + Supabase Database + Hetzner Cloud  
**Target Deployment**: Production-ready scalable infrastructure  
**Implementation Timeline**: 5-7 days for core functionality  

---

## 🏗 System Architecture Overview

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Client  │    │  FastAPI Server │    │   Supabase DB   │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────►│ Hetzner Cloud   │◄─────────────┘
                        │ Infrastructure  │
                        └─────────────────┘
```

### Technology Stack Details

#### Backend Stack
- **FastAPI 0.104+**: High-performance async Python framework
- **Pydantic 2.5+**: Data validation and serialization
- **SQLAlchemy 2.0+**: ORM with async support
- **Asyncpg**: High-performance PostgreSQL adapter
- **Redis**: Caching and session management
- **Celery**: Background task processing
- **Python 3.11+**: Latest stable Python version

#### Database Stack
- **Supabase**: PostgreSQL-as-a-Service with built-in features
- **PostgreSQL 15+**: Core database engine
- **Row Level Security (RLS)**: Built-in authorization
- **Real-time subscriptions**: WebSocket support
- **PostgREST**: Auto-generated REST API
- **Storage**: File upload and management

#### Infrastructure Stack
- **Hetzner Cloud**: Cost-effective European hosting
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **Nginx**: Reverse proxy and load balancing
- **Let's Encrypt**: SSL/TLS certificates
- **GitHub Actions**: CI/CD pipeline

---

## 📊 Database Design (Supabase/PostgreSQL)

### Core Tables Schema

#### 1. Organizations Table
```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan_type VARCHAR(50) DEFAULT 'free',
    api_key_hash VARCHAR(255),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- RLS Policy
CREATE POLICY "Users can view their organization" ON organizations
    FOR SELECT USING (auth.uid() IN (
        SELECT user_id FROM organization_members WHERE organization_id = id
    ));
```

#### 2. Projects Table
```sql
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    repository_url VARCHAR(500),
    branch_name VARCHAR(100) DEFAULT 'main',
    scan_config JSONB DEFAULT '{
        "sast_enabled": true,
        "sca_enabled": true,
        "secrets_enabled": true,
        "iac_enabled": true,
        "container_enabled": true,
        "auto_fix_enabled": true,
        "severity_threshold": "medium"
    }',
    github_integration JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, slug)
);

-- Indexes for performance
CREATE INDEX idx_projects_org_id ON projects(organization_id);
CREATE INDEX idx_projects_status ON projects(status);
```

#### 3. Scans Table
```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- 'full', 'incremental', 'pr'
    trigger_type VARCHAR(50) NOT NULL, -- 'manual', 'webhook', 'scheduled'
    commit_sha VARCHAR(40),
    branch_name VARCHAR(100),
    pr_number INTEGER,
    status VARCHAR(50) DEFAULT 'queued', -- 'queued', 'running', 'completed', 'failed'
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    scan_stats JSONB DEFAULT '{
        "files_scanned": 0,
        "lines_scanned": 0,
        "rules_executed": 0,
        "findings_count": 0,
        "auto_fixes_applied": 0
    }',
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
```

#### 4. Findings Table
```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    
    -- Finding Classification
    finding_type VARCHAR(50) NOT NULL, -- 'sast', 'sca', 'secrets', 'iac', 'container'
    rule_id VARCHAR(200) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
    category VARCHAR(100) NOT NULL,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    
    -- Location Information
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,
    code_snippet TEXT,
    
    -- Finding Details
    title VARCHAR(500) NOT NULL,
    description TEXT,
    message TEXT,
    confidence VARCHAR(20) DEFAULT 'medium', -- 'high', 'medium', 'low'
    
    -- Fix Information
    fix_available BOOLEAN DEFAULT FALSE,
    fix_confidence REAL DEFAULT 0.0, -- 0.0 to 1.0
    fix_suggestion TEXT,
    fix_code TEXT,
    fix_applied BOOLEAN DEFAULT FALSE,
    fix_applied_at TIMESTAMPTZ,
    
    -- Metadata
    fingerprint VARCHAR(64) NOT NULL, -- SHA256 hash for deduplication
    status VARCHAR(50) DEFAULT 'new', -- 'new', 'reviewed', 'fixed', 'ignored'
    false_positive BOOLEAN DEFAULT FALSE,
    suppressed BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(project_id, fingerprint)
);

-- Indexes for performance
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_project_id ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_type_severity ON findings(finding_type, severity);
```

#### 5. Auto-Fix History Table
```sql
CREATE TABLE autofix_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    
    -- Fix Details
    fix_type VARCHAR(50) NOT NULL, -- 'pattern_based', 'ai_generated', 'manual'
    original_code TEXT NOT NULL,
    fixed_code TEXT NOT NULL,
    fix_pattern_id VARCHAR(100),
    confidence_score REAL NOT NULL, -- 0.0 to 1.0
    
    -- Application Status
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'applied', 'failed', 'rolled_back'
    pr_number INTEGER,
    commit_sha VARCHAR(40),
    applied_at TIMESTAMPTZ,
    
    -- Effectiveness Tracking
    developer_feedback VARCHAR(20), -- 'approved', 'rejected', 'modified'
    effectiveness_score REAL, -- 0.0 to 1.0 (learning feedback)
    rollback_reason TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_autofix_finding_id ON autofix_history(finding_id);
CREATE INDEX idx_autofix_project_id ON autofix_history(project_id);
CREATE INDEX idx_autofix_status ON autofix_history(status);
```

#### 6. Scan Rules Table
```sql
CREATE TABLE scan_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(200) UNIQUE NOT NULL,
    rule_type VARCHAR(50) NOT NULL, -- 'sast', 'sca', 'secrets', 'iac', 'container'
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    cwe_mapping JSONB DEFAULT '[]',
    owasp_mapping JSONB DEFAULT '[]',
    languages JSONB DEFAULT '[]', -- ['python', 'javascript', 'java']
    pattern_definition JSONB NOT NULL,
    fix_patterns JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT TRUE,
    custom_rule BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_rules_type ON scan_rules(rule_type);
CREATE INDEX idx_rules_enabled ON scan_rules(enabled);
CREATE INDEX idx_rules_custom ON scan_rules(custom_rule);
```

### Supabase Configuration

#### Row Level Security (RLS) Policies
```sql
-- Organizations access control
CREATE POLICY "org_members_access" ON organizations
    FOR ALL USING (
        auth.uid() IN (
            SELECT user_id FROM organization_members 
            WHERE organization_id = id
        )
    );

-- Projects access control
CREATE POLICY "project_org_access" ON projects
    FOR ALL USING (
        organization_id IN (
            SELECT organization_id FROM organization_members 
            WHERE user_id = auth.uid()
        )
    );

-- Findings access control
CREATE POLICY "findings_project_access" ON findings
    FOR ALL USING (
        project_id IN (
            SELECT p.id FROM projects p
            JOIN organization_members om ON p.organization_id = om.organization_id
            WHERE om.user_id = auth.uid()
        )
    );
```

#### Real-time Subscriptions
```sql
-- Enable real-time for scan status updates
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
ALTER PUBLICATION supabase_realtime ADD TABLE findings;
ALTER PUBLICATION supabase_realtime ADD TABLE autofix_history;
```

---

## 🚀 FastAPI Application Architecture

### Project Structure
```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── config.py              # Configuration management
│   ├── dependencies.py        # Dependency injection
│   ├── middleware.py          # Custom middleware
│   │
│   ├── core/                  # Core business logic
│   │   ├── __init__.py
│   │   ├── models.py          # SQLAlchemy models
│   │   ├── schemas.py         # Pydantic schemas
│   │   ├── database.py        # Database connection
│   │   ├── security.py        # Authentication/authorization
│   │   └── exceptions.py      # Custom exceptions
│   │
│   ├── api/                   # API routes
│   │   ├── __init__.py
│   │   ├── deps.py           # Route dependencies
│   │   └── v1/               # API version 1
│   │       ├── __init__.py
│   │       ├── router.py     # Main router
│   │       ├── auth.py       # Authentication routes
│   │       ├── projects.py   # Project management
│   │       ├── scans.py      # Scan operations
│   │       ├── findings.py   # Findings management
│   │       └── autofix.py    # Auto-fix operations
│   │
│   ├── services/              # Business logic services
│   │   ├── __init__.py
│   │   ├── scan_service.py    # Scan orchestration
│   │   ├── autofix_service.py # Auto-fix logic
│   │   ├── github_service.py  # GitHub integration
│   │   └── notification_service.py # Notifications
│   │
│   ├── scanners/              # Security scanning engines
│   │   ├── __init__.py
│   │   ├── base.py           # Base scanner interface
│   │   ├── sast_scanner.py   # SAST implementation
│   │   ├── sca_scanner.py    # SCA implementation
│   │   ├── secrets_scanner.py # Secrets scanning
│   │   ├── iac_scanner.py    # IaC scanning
│   │   └── container_scanner.py # Container scanning
│   │
│   ├── autofix/               # Auto-fix engine
│   │   ├── __init__.py
│   │   ├── engine.py         # Main auto-fix engine
│   │   ├── patterns.py       # Fix patterns database
│   │   ├── ai_fixes.py       # AI-powered fixes
│   │   └── validators.py     # Fix validation
│   │
│   ├── workers/               # Background tasks
│   │   ├── __init__.py
│   │   ├── celery_app.py     # Celery configuration
│   │   ├── scan_tasks.py     # Scanning tasks
│   │   └── autofix_tasks.py  # Auto-fix tasks
│   │
│   └── utils/                 # Utility functions
│       ├── __init__.py
│       ├── git.py            # Git operations
│       ├── github.py         # GitHub API client
│       ├── cache.py          # Redis caching
│       └── metrics.py        # Metrics collection
│
├── tests/                     # Test suite
├── alembic/                   # Database migrations
├── docker/                    # Docker configurations
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Container image
└── docker-compose.yml         # Development setup
```

### Core Application Configuration

#### `app/config.py`
```python
from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "DevSecure API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    
    # Database (Supabase)
    SUPABASE_URL: str
    SUPABASE_KEY: str
    SUPABASE_JWT_SECRET: str
    DATABASE_URL: str  # PostgreSQL connection string
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # GitHub Integration
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_APP_PRIVATE_KEY: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    
    # OpenAI (for AI fixes)
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    
    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_MIN_LENGTH: int = 8
    
    # Scanning
    SCAN_TIMEOUT_MINUTES: int = 30
    MAX_FILE_SIZE_MB: int = 10
    MAX_SCAN_RESULTS: int = 10000
    
    # Auto-fix
    AUTOFIX_ENABLED: bool = True
    AUTOFIX_CONFIDENCE_THRESHOLD: float = 0.7
    MAX_FIXES_PER_PR: int = 20
    
    # Monitoring
    SENTRY_DSN: Optional[str] = None
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

#### `app/main.py`
```python
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.middleware import (
    LoggingMiddleware,
    RateLimitMiddleware,
    MetricsMiddleware,
)
from app.api.v1.router import api_router
from app.core.exceptions import DevSecureException
from app.core.database import engine
from app.workers.celery_app import celery_app
import logging

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="DevSecure Unified Security Platform API",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["https://app.devsecure.io"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Security middleware
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["app.devsecure.io", "api.devsecure.io"]
    )

# Custom middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(MetricsMiddleware)

# Include API routes
app.include_router(api_router, prefix="/api/v1")

# Exception handlers
@app.exception_handler(DevSecureException)
async def devsecure_exception_handler(request: Request, exc: DevSecureException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_type,
            "message": exc.message,
            "details": exc.details
        }
    )

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return await http_exception_handler(request, exc)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return await request_validation_exception_handler(request, exc)

# Health check endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint for load balancer"""
    return {"status": "healthy", "version": settings.VERSION}

@app.get("/ready")
async def readiness_check():
    """Readiness check for Kubernetes"""
    try:
        # Check database connection
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        
        # Check Redis connection
        from app.utils.cache import redis_client
        await redis_client.ping()
        
        return {"status": "ready"}
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not ready", "error": str(e)}
        )

# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    
    # Initialize services
    from app.services.scan_service import ScanService
    from app.services.autofix_service import AutoFixService
    
    # Start background task monitoring
    if settings.DEBUG:
        logger.info("Application started in DEBUG mode")

# Shutdown event  
@app.on_event("shutdown")
async def shutdown_event():
    logger.info(f"Shutting down {settings.APP_NAME}")
    
    # Close database connections
    await engine.dispose()
    
    # Close Redis connections
    from app.utils.cache import redis_client
    await redis_client.close()
```

### Database Connection (Supabase Integration)

#### `app/core/database.py`
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Create async engine for Supabase PostgreSQL
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    poolclass=NullPool,  # Supabase handles connection pooling
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Create declarative base
Base = declarative_base()

# Dependency for getting database session
async def get_db_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

# Supabase client for real-time and auth
from supabase import create_client, Client
from typing import Optional

class SupabaseClient:
    def __init__(self):
        self.client: Optional[Client] = None
        
    def initialize(self):
        """Initialize Supabase client"""
        self.client = create_client(
            settings.SUPABASE_URL,
            settings.SUPABASE_KEY
        )
        return self.client
    
    def get_client(self) -> Client:
        """Get Supabase client instance"""
        if not self.client:
            self.initialize()
        return self.client

supabase_client = SupabaseClient()
```

### API Route Definitions

#### `app/api/v1/scans.py`
```python
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.core.database import get_db_session
from app.core.schemas import (
    ScanCreate,
    ScanResponse,
    ScanDetail,
    ScanStats,
    FindingResponse
)
from app.core.models import Scan, Project, Finding
from app.services.scan_service import ScanService
from app.api.deps import get_current_user, get_project_access
from app.workers.scan_tasks import start_scan_task

router = APIRouter()

@router.post("/", response_model=ScanResponse)
async def create_scan(
    project_id: uuid.UUID,
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    current_user = Depends(get_current_user),
    project = Depends(get_project_access)
):
    """
    Create a new security scan for a project
    
    This endpoint initiates a comprehensive security scan including:
    - SAST (Static Application Security Testing)
    - SCA (Software Composition Analysis) 
    - Secrets Detection
    - IaC (Infrastructure as Code) Security
    - Container Security Analysis
    """
    scan_service = ScanService(db)
    
    # Create scan record
    scan = await scan_service.create_scan(
        project_id=project_id,
        scan_type=scan_data.scan_type,
        trigger_type=scan_data.trigger_type,
        commit_sha=scan_data.commit_sha,
        branch_name=scan_data.branch_name,
        pr_number=scan_data.pr_number
    )
    
    # Start background scan task
    background_tasks.add_task(
        start_scan_task.delay,
        str(scan.id),
        scan_data.dict()
    )
    
    return ScanResponse.from_orm(scan)

@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get detailed scan information including findings"""
    scan_service = ScanService(db)
    
    scan = await scan_service.get_scan_with_findings(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check user access to project
    await get_project_access(scan.project_id, current_user)
    
    return ScanDetail.from_orm(scan)

@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: uuid.UUID,
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low|info)$"),
    finding_type: Optional[str] = Query(None, regex="^(sast|sca|secrets|iac|container)$"),
    status: Optional[str] = Query(None, regex="^(new|reviewed|fixed|ignored)$"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get paginated findings for a specific scan with filtering"""
    scan_service = ScanService(db)
    
    # Verify scan exists and user has access
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await get_project_access(scan.project_id, current_user)
    
    # Get filtered findings
    findings = await scan_service.get_scan_findings(
        scan_id=scan_id,
        severity=severity,
        finding_type=finding_type,
        status=status,
        limit=limit,
        offset=offset
    )
    
    return [FindingResponse.from_orm(finding) for finding in findings]

@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Cancel a running scan"""
    scan_service = ScanService(db)
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await get_project_access(scan.project_id, current_user)
    
    if scan.status not in ['queued', 'running']:
        raise HTTPException(
            status_code=400, 
            detail="Can only cancel queued or running scans"
        )
    
    # Cancel the background task
    from app.workers.celery_app import celery_app
    celery_app.control.revoke(str(scan_id), terminate=True)
    
    # Update scan status
    await scan_service.update_scan_status(scan_id, 'cancelled')
    
    return {"message": "Scan cancelled successfully"}

@router.get("/{scan_id}/stats", response_model=ScanStats)
async def get_scan_stats(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get statistical summary of scan results"""
    scan_service = ScanService(db)
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await get_project_access(scan.project_id, current_user)
    
    stats = await scan_service.get_scan_statistics(scan_id)
    return stats
```

### Background Task Processing (Celery)

#### `app/workers/scan_tasks.py`
```python
from celery import Celery
from app.workers.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.services.scan_service import ScanService
from app.scanners.sast_scanner import SASTScanner
from app.scanners.sca_scanner import SCAScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.iac_scanner import IaCScanner
from app.scanners.container_scanner import ContainerScanner
from app.services.autofix_service import AutoFixService
import asyncio
import logging
import uuid
from typing import Dict, Any

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, max_retries=3)
def start_scan_task(self, scan_id: str, scan_config: Dict[str, Any]):
    """
    Main scan orchestration task
    
    This task coordinates the execution of all security scanning engines
    and triggers auto-fix generation for discovered findings.
    """
    try:
        # Run the async scan in event loop
        return asyncio.run(execute_scan(scan_id, scan_config))
    except Exception as exc:
        logger.error(f"Scan task failed for scan {scan_id}: {exc}")
        
        # Update scan status to failed
        asyncio.run(update_scan_status(scan_id, 'failed', str(exc)))
        
        # Retry task if not max retries reached
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan {scan_id} (attempt {self.request.retries + 1})")
            raise self.retry(countdown=60 * (2 ** self.request.retries))
        
        raise exc

async def execute_scan(scan_id: str, scan_config: Dict[str, Any]):
    """Execute the complete security scan workflow"""
    async with AsyncSessionLocal() as db:
        scan_service = ScanService(db)
        autofix_service = AutoFixService(db)
        
        # Update scan status to running
        await scan_service.update_scan_status(uuid.UUID(scan_id), 'running')
        
        try:
            # Get scan and project details
            scan = await scan_service.get_scan(uuid.UUID(scan_id))
            project = await scan_service.get_project(scan.project_id)
            
            # Clone repository if needed
            repo_path = await clone_repository(project.repository_url, scan.commit_sha)
            
            # Initialize scanners
            scanners = []
            if scan_config.get('sast_enabled', True):
                scanners.append(SASTScanner())
            if scan_config.get('sca_enabled', True):
                scanners.append(SCAScanner())
            if scan_config.get('secrets_enabled', True):
                scanners.append(SecretsScanner())
            if scan_config.get('iac_enabled', True):
                scanners.append(IaCScanner())
            if scan_config.get('container_enabled', True):
                scanners.append(ContainerScanner())
            
            # Execute all scanners
            all_findings = []
            scan_stats = {
                'files_scanned': 0,
                'lines_scanned': 0,
                'rules_executed': 0,
                'findings_count': 0,
                'auto_fixes_applied': 0
            }
            
            for scanner in scanners:
                logger.info(f"Running {scanner.__class__.__name__} for scan {scan_id}")
                
                scanner_results = await scanner.scan(
                    repo_path=repo_path,
                    config=scan_config
                )
                
                # Process findings
                findings = await scan_service.create_findings(
                    scan_id=uuid.UUID(scan_id),
                    project_id=scan.project_id,
                    scanner_results=scanner_results
                )
                
                all_findings.extend(findings)
                
                # Update stats
                scan_stats['files_scanned'] += scanner_results.get('files_scanned', 0)
                scan_stats['lines_scanned'] += scanner_results.get('lines_scanned', 0)
                scan_stats['rules_executed'] += scanner_results.get('rules_executed', 0)
            
            scan_stats['findings_count'] = len(all_findings)
            
            # Generate auto-fixes if enabled
            if scan_config.get('auto_fix_enabled', True) and all_findings:
                logger.info(f"Generating auto-fixes for {len(all_findings)} findings")
                
                fixes_applied = await autofix_service.generate_fixes_for_findings(
                    findings=all_findings,
                    confidence_threshold=scan_config.get('confidence_threshold', 0.7)
                )
                
                scan_stats['auto_fixes_applied'] = fixes_applied
            
            # Update scan completion
            await scan_service.complete_scan(
                scan_id=uuid.UUID(scan_id),
                stats=scan_stats
            )
            
            logger.info(f"Scan {scan_id} completed successfully")
            return {
                'status': 'completed',
                'findings_count': len(all_findings),
                'fixes_applied': scan_stats['auto_fixes_applied']
            }
            
        except Exception as e:
            logger.error(f"Scan execution failed: {e}")
            await scan_service.update_scan_status(
                uuid.UUID(scan_id), 
                'failed', 
                str(e)
            )
            raise
        
        finally:
            # Cleanup repository
            if 'repo_path' in locals():
                await cleanup_repository(repo_path)

async def clone_repository(repo_url: str, commit_sha: str) -> str:
    """Clone repository and checkout specific commit"""
    import tempfile
    import subprocess
    import os
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix='devsecure_scan_')
    
    try:
        # Clone repository
        subprocess.run([
            'git', 'clone', '--depth=1', repo_url, temp_dir
        ], check=True, capture_output=True)
        
        # Checkout specific commit if provided
        if commit_sha:
            subprocess.run([
                'git', 'checkout', commit_sha
            ], cwd=temp_dir, check=True, capture_output=True)
        
        return temp_dir
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        # Cleanup on failure
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

async def cleanup_repository(repo_path: str):
    """Clean up cloned repository"""
    import shutil
    try:
        shutil.rmtree(repo_path, ignore_errors=True)
        logger.info(f"Cleaned up repository at {repo_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup repository: {e}")

async def update_scan_status(scan_id: str, status: str, error_message: str = None):
    """Update scan status in database"""
    async with AsyncSessionLocal() as db:
        scan_service = ScanService(db)
        await scan_service.update_scan_status(
            uuid.UUID(scan_id), 
            status, 
            error_message
        )
```

---

## 🌐 Hetzner Cloud Infrastructure

### Server Specifications

#### Production Server Configuration
```yaml
# Hetzner Cloud Server Specs
server_type: CPX51  # 8 vCPUs, 16GB RAM, 240GB NVMe SSD
location: nbg1      # Nuremberg, Germany (EU GDPR compliant)
image: ubuntu-22.04 # Ubuntu 22.04 LTS

# Monthly Cost: €29.90 (~$32/month)
# Features:
# - 20TB traffic included
# - IPv4 & IPv6 support  
# - Local SSD storage
# - 99.9% uptime SLA
```

#### Load Balancer Configuration
```yaml
# Hetzner Load Balancer
load_balancer_type: lb11  # Up to 5,000 concurrent connections
algorithm: round_robin
health_check:
  protocol: http
  port: 8000
  path: /health
  interval: 15
  timeout: 10
  retries: 3

# SSL Certificate (Let's Encrypt)
certificate:
  type: managed
  domains:
    - api.devsecure.io
    - app.devsecure.io
```

### Docker Deployment Configuration

#### `docker-compose.prod.yml`
```yaml
version: '3.8'

services:
  # FastAPI Application
  api:
    build:
      context: .
      dockerfile: docker/Dockerfile.prod
    image: devsecure/api:latest
    restart: always
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=${DATABASE_URL}
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_KEY=${SUPABASE_KEY}
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - GITHUB_APP_ID=${GITHUB_APP_ID}
      - GITHUB_APP_PRIVATE_KEY=${GITHUB_APP_PRIVATE_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    ports:
      - "8000:8000"
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs
      - /var/run/docker.sock:/var/run/docker.sock  # For container scanning
    networks:
      - devsecure_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Redis Cache
  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - devsecure_network
    healthcheck:
      test: ["CMD", "redis-cli", "auth", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Celery Worker
  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.prod
    image: devsecure/api:latest
    restart: always
    command: celery -A app.workers.celery_app worker --loglevel=info --concurrency=4
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=${DATABASE_URL}
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_KEY=${SUPABASE_KEY}
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - GITHUB_APP_ID=${GITHUB_APP_ID}
      - GITHUB_APP_PRIVATE_KEY=${GITHUB_APP_PRIVATE_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs
      - /var/run/docker.sock:/var/run/docker.sock
      - /tmp:/tmp  # For temporary repositories
    networks:
      - devsecure_network

  # Celery Beat (Scheduler)
  scheduler:
    build:
      context: .
      dockerfile: docker/Dockerfile.prod
    image: devsecure/api:latest
    restart: always
    command: celery -A app.workers.celery_app beat --loglevel=info
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs
    networks:
      - devsecure_network

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./docker/nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./docker/ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - api
    networks:
      - devsecure_network

volumes:
  redis_data:
    driver: local

networks:
  devsecure_network:
    driver: bridge
```

#### `docker/Dockerfile.prod`
```dockerfile
# Multi-stage build for production
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash app

# Set work directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/app/.local

# Copy application code
COPY . .

# Set ownership
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Make sure scripts are executable
RUN chmod +x /app/docker/entrypoint.sh

# Add local bin to PATH
ENV PATH=/home/app/.local/bin:$PATH

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start application
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### CI/CD Pipeline (GitHub Actions)

#### `.github/workflows/deploy.yml`
```yaml
name: Deploy to Hetzner Cloud

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: devsecure/api

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: devsecure_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-asyncio pytest-cov
    
    - name: Run tests
      run: |
        pytest tests/ -v --cov=app --cov-report=xml
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost/devsecure_test
        REDIS_URL: redis://localhost:6379/0
        SECRET_KEY: test-secret-key-for-ci
        SUPABASE_URL: http://localhost:54321
        SUPABASE_KEY: test-key
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    permissions:
      contents: read
      packages: write

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: docker/Dockerfile.prod
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
    
    - name: Deploy to Hetzner Cloud
      uses: appleboy/ssh-action@v1.0.0
      with:
        host: ${{ secrets.HETZNER_HOST }}
        username: ${{ secrets.HETZNER_USER }}
        key: ${{ secrets.HETZNER_SSH_KEY }}
        script: |
          # Navigate to application directory
          cd /opt/devsecure
          
          # Pull latest code
          git pull origin main
          
          # Update environment variables
          echo "${{ secrets.ENV_PRODUCTION }}" > .env
          
          # Pull latest Docker images
          docker-compose -f docker-compose.prod.yml pull
          
          # Restart services with zero-downtime
          docker-compose -f docker-compose.prod.yml up -d --remove-orphans
          
          # Run database migrations
          docker-compose -f docker-compose.prod.yml exec -T api alembic upgrade head
          
          # Health check
          sleep 30
          curl -f http://localhost:8000/health || exit 1
          
          # Cleanup old images
          docker image prune -f
```

### Server Setup Script

#### `deploy/setup_hetzner.sh`
```bash
#!/bin/bash
set -e

# DevSecure Hetzner Cloud Setup Script
# This script configures a fresh Ubuntu 22.04 server

echo "🚀 Setting up DevSecure on Hetzner Cloud..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    nginx \
    certbot \
    python3-certbot-nginx \
    htop \
    fail2ban \
    ufw

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# Configure fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Create application directory
sudo mkdir -p /opt/devsecure
sudo chown $USER:$USER /opt/devsecure

# Clone repository
cd /opt/devsecure
git clone https://github.com/quadriconsulting/devsecure.git .

# Create environment file template
cat > .env.template << 'EOF'
# Application
ENVIRONMENT=production
SECRET_KEY=your-secret-key-here
DEBUG=false

# Database (Supabase)
DATABASE_URL=postgresql://username:password@db.supabase.co:5432/postgres
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key-here
SUPABASE_JWT_SECRET=your-jwt-secret-here

# Redis
REDIS_PASSWORD=your-redis-password-here

# GitHub Integration
GITHUB_APP_ID=your-github-app-id
GITHUB_APP_PRIVATE_KEY=your-github-private-key
GITHUB_WEBHOOK_SECRET=your-webhook-secret

# OpenAI
OPENAI_API_KEY=your-openai-api-key

# Monitoring
SENTRY_DSN=your-sentry-dsn
EOF

# Configure Nginx
sudo tee /etc/nginx/sites-available/devsecure << 'EOF'
server {
    listen 80;
    server_name api.devsecure.io app.devsecure.io;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://localhost:8000/health;
        access_log off;
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/devsecure /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

# Create systemd service for automatic startup
sudo tee /etc/systemd/system/devsecure.service << 'EOF'
[Unit]
Description=DevSecure Application
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/devsecure
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable devsecure.service

# Create log rotation
sudo tee /etc/logrotate.d/devsecure << 'EOF'
/opt/devsecure/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker compose -f /opt/devsecure/docker-compose.prod.yml exec api kill -USR1 1
    endscript
}
EOF

# Setup monitoring script
tee /opt/devsecure/monitor.sh << 'EOF'
#!/bin/bash
# Simple health monitoring script

HEALTH_URL="http://localhost:8000/health"
LOG_FILE="/opt/devsecure/logs/monitor.log"

# Check if application is healthy
if curl -f -s $HEALTH_URL > /dev/null; then
    echo "$(date): Application is healthy" >> $LOG_FILE
else
    echo "$(date): Application is unhealthy, restarting..." >> $LOG_FILE
    systemctl restart devsecure
fi
EOF

chmod +x /opt/devsecure/monitor.sh

# Add monitoring to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/devsecure/monitor.sh") | crontab -

echo "✅ Hetzner Cloud setup completed!"
echo ""
echo "Next steps:"
echo "1. Configure your .env file with actual values"
echo "2. Run: docker compose -f docker-compose.prod.yml up -d"
echo "3. Setup SSL: sudo certbot --nginx -d api.devsecure.io -d app.devsecure.io"
echo "4. Configure your domain DNS to point to this server"
echo ""
echo "Server IP: $(curl -s ifconfig.me)"
```

---

## 🔌 API Integration Examples

### Supabase Integration Examples

#### Real-time Scan Updates
```typescript
// Frontend WebSocket connection for real-time updates
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.REACT_APP_SUPABASE_URL,
  process.env.REACT_APP_SUPABASE_ANON_KEY
)

// Subscribe to scan status changes
const scanSubscription = supabase
  .channel('scan-updates')
  .on(
    'postgres_changes',
    {
      event: 'UPDATE',
      schema: 'public',
      table: 'scans',
      filter: `project_id=in.(${userProjectIds.join(',')})`
    },
    (payload) => {
      console.log('Scan updated:', payload.new)
      // Update UI with new scan status
      updateScanStatus(payload.new)
    }
  )
  .subscribe()

// Subscribe to new findings
const findingsSubscription = supabase
  .channel('findings-updates')
  .on(
    'postgres_changes',
    {
      event: 'INSERT',
      schema: 'public',
      table: 'findings'
    },
    (payload) => {
      console.log('New finding:', payload.new)
      addFindingToUI(payload.new)
    }
  )
  .subscribe()
```

### GitHub Integration Example

#### `app/services/github_service.py`
```python
from typing import List, Dict, Any, Optional
import httpx
import jwt
import time
from datetime import datetime, timedelta
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class GitHubService:
    def __init__(self):
        self.app_id = settings.GITHUB_APP_ID
        self.private_key = settings.GITHUB_APP_PRIVATE_KEY
        self.base_url = "https://api.github.com"
        
    def _generate_jwt_token(self) -> str:
        """Generate JWT token for GitHub App authentication"""
        now = int(time.time())
        payload = {
            'iat': now - 60,  # Issued 60 seconds ago
            'exp': now + (10 * 60),  # Expire in 10 minutes
            'iss': self.app_id
        }
        
        return jwt.encode(payload, self.private_key, algorithm='RS256')
    
    async def get_installation_token(self, installation_id: str) -> str:
        """Get installation access token"""
        jwt_token = self._generate_jwt_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/app/installations/{installation_id}/access_tokens",
                headers={
                    'Authorization': f'Bearer {jwt_token}',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            response.raise_for_status()
            
            token_data = response.json()
            return token_data['token']
    
    async def create_pull_request(
        self,
        repo_owner: str,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
        installation_id: str = None
    ) -> Dict[str, Any]:
        """Create a pull request with auto-fixes"""
        
        token = await self.get_installation_token(installation_id)
        
        pr_data = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "maintainer_can_modify": True
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/pulls",
                headers={
                    'Authorization': f'token {token}',
                    'Accept': 'application/vnd.github.v3+json'
                },
                json=pr_data
            )
            
            if response.status_code == 201:
                pr_info = response.json()
                logger.info(f"Created PR #{pr_info['number']}: {title}")
                return pr_info
            else:
                logger.error(f"Failed to create PR: {response.text}")
                response.raise_for_status()
    
    async def create_commit_with_fixes(
        self,
        repo_owner: str,
        repo_name: str,
        branch_name: str,
        fixes: List[Dict[str, Any]],
        installation_id: str
    ) -> str:
        """Create a commit with multiple auto-fixes"""
        
        token = await self.get_installation_token(installation_id)
        
        # Get current commit SHA
        current_commit = await self._get_branch_commit(
            repo_owner, repo_name, branch_name, token
        )
        
        # Create tree with fixes
        tree_items = []
        for fix in fixes:
            tree_items.append({
                "path": fix['file_path'],
                "mode": "100644",
                "type": "blob",
                "content": fix['fixed_content']
            })
        
        # Create new tree
        tree_sha = await self._create_tree(
            repo_owner, repo_name, tree_items, current_commit['tree']['sha'], token
        )
        
        # Create commit
        commit_message = f"🔧 DevSecure Auto-Fix: {len(fixes)} security issues resolved\n\n"
        commit_message += "\n".join([
            f"- {fix['finding_title']} ({fix['severity']})"
            for fix in fixes[:10]  # Limit to first 10 in message
        ])
        
        if len(fixes) > 10:
            commit_message += f"\n... and {len(fixes) - 10} more fixes"
        
        commit_sha = await self._create_commit(
            repo_owner, repo_name, commit_message, tree_sha, 
            current_commit['sha'], token
        )
        
        # Update branch
        await self._update_branch(repo_owner, repo_name, branch_name, commit_sha, token)
        
        return commit_sha
    
    async def _get_branch_commit(
        self, repo_owner: str, repo_name: str, branch: str, token: str
    ) -> Dict[str, Any]:
        """Get the latest commit for a branch"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/refs/heads/{branch}",
                headers={'Authorization': f'token {token}'}
            )
            response.raise_for_status()
            
            ref_data = response.json()
            commit_sha = ref_data['object']['sha']
            
            # Get commit details
            commit_response = await client.get(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/commits/{commit_sha}",
                headers={'Authorization': f'token {token}'}
            )
            commit_response.raise_for_status()
            
            return commit_response.json()
    
    async def _create_tree(
        self, repo_owner: str, repo_name: str, tree_items: List[Dict],
        base_tree: str, token: str
    ) -> str:
        """Create a new tree with file changes"""
        async with httpx.AsyncClient() as client:
            tree_data = {
                "base_tree": base_tree,
                "tree": tree_items
            }
            
            response = await client.post(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/trees",
                headers={'Authorization': f'token {token}'},
                json=tree_data
            )
            response.raise_for_status()
            
            return response.json()['sha']
    
    async def _create_commit(
        self, repo_owner: str, repo_name: str, message: str,
        tree_sha: str, parent_sha: str, token: str
    ) -> str:
        """Create a new commit"""
        async with httpx.AsyncClient() as client:
            commit_data = {
                "message": message,
                "tree": tree_sha,
                "parents": [parent_sha],
                "author": {
                    "name": "DevSecure Bot",
                    "email": "bot@devsecure.io",
                    "date": datetime.utcnow().isoformat() + "Z"
                }
            }
            
            response = await client.post(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/commits",
                headers={'Authorization': f'token {token}'},
                json=commit_data
            )
            response.raise_for_status()
            
            return response.json()['sha']
    
    async def _update_branch(
        self, repo_owner: str, repo_name: str, branch: str,
        commit_sha: str, token: str
    ):
        """Update branch to point to new commit"""
        async with httpx.AsyncClient() as client:
            update_data = {
                "sha": commit_sha,
                "force": False
            }
            
            response = await client.patch(
                f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/refs/heads/{branch}",
                headers={'Authorization': f'token {token}'},
                json=update_data
            )
            response.raise_for_status()
```

---

## 📊 Performance & Monitoring

### Metrics Collection

#### `app/utils/metrics.py`
```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import logging
from functools import wraps
from typing import Callable, Any
import asyncio

logger = logging.getLogger(__name__)

# Metrics definitions
REQUEST_COUNT = Counter(
    'devsecure_requests_total', 
    'Total requests', 
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'devsecure_request_duration_seconds',
    'Request duration',
    ['method', 'endpoint']
)

SCAN_COUNT = Counter(
    'devsecure_scans_total',
    'Total scans',
    ['scan_type', 'status']
)

SCAN_DURATION = Histogram(
    'devsecure_scan_duration_seconds',
    'Scan duration',
    ['scan_type']
)

FINDINGS_COUNT = Counter(
    'devsecure_findings_total',
    'Total findings',
    ['finding_type', 'severity']
)

AUTOFIX_COUNT = Counter(
    'devsecure_autofixes_total',
    'Total auto-fixes',
    ['fix_type', 'status']
)

ACTIVE_SCANS = Gauge(
    'devsecure_active_scans',
    'Currently active scans'
)

def track_request_metrics(func: Callable) -> Callable:
    """Decorator to track request metrics"""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        start_time = time.time()
        status = "success"
        
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            status = "error"
            raise
        finally:
            duration = time.time() - start_time
            
            # Extract method and endpoint from request
            if args and hasattr(args[0], 'method'):
                method = args[0].method
                endpoint = args[0].url.path
            else:
                method = "unknown"
                endpoint = "unknown"
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status=status
            ).inc()
            
            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        start_time = time.time()
        status = "success"
        
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            status = "error"
            raise
        finally:
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                method="unknown",
                endpoint="unknown"
            ).observe(duration)
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

def track_scan_metrics(scan_type: str):
    """Decorator to track scan metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            ACTIVE_SCANS.inc()
            start_time = time.time()
            status = "success"
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                ACTIVE_SCANS.dec()
                duration = time.time() - start_time
                
                SCAN_COUNT.labels(
                    scan_type=scan_type,
                    status=status
                ).inc()
                
                SCAN_DURATION.labels(
                    scan_type=scan_type
                ).observe(duration)
        
        return wrapper
    return decorator

def record_finding(finding_type: str, severity: str):
    """Record a new finding"""
    FINDINGS_COUNT.labels(
        finding_type=finding_type,
        severity=severity
    ).inc()

def record_autofix(fix_type: str, status: str):
    """Record an auto-fix attempt"""
    AUTOFIX_COUNT.labels(
        fix_type=fix_type,
        status=status
    ).inc()

def start_metrics_server(port: int = 8001):
    """Start Prometheus metrics server"""
    try:
        start_http_server(port)
        logger.info(f"Metrics server started on port {port}")
    except Exception as e:
        logger.error(f"Failed to start metrics server: {e}")
```

### Health Monitoring

#### `app/core/health.py`
```python
from typing import Dict, Any
import asyncio
import time
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import engine
from app.utils.cache import redis_client
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class HealthChecker:
    def __init__(self):
        self.checks = {
            'database': self._check_database,
            'redis': self._check_redis,
            'supabase': self._check_supabase,
            'disk_space': self._check_disk_space,
            'memory': self._check_memory,
        }
    
    async def run_health_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        results = {
            'status': 'healthy',
            'timestamp': int(time.time()),
            'checks': {}
        }
        
        overall_healthy = True
        
        for check_name, check_func in self.checks.items():
            try:
                start_time = time.time()
                check_result = await check_func()
                duration = (time.time() - start_time) * 1000  # ms
                
                results['checks'][check_name] = {
                    'status': 'healthy' if check_result['healthy'] else 'unhealthy',
                    'message': check_result.get('message', ''),
                    'duration_ms': round(duration, 2),
                    'details': check_result.get('details', {})
                }
                
                if not check_result['healthy']:
                    overall_healthy = False
                    
            except Exception as e:
                logger.error(f"Health check {check_name} failed: {e}")
                results['checks'][check_name] = {
                    'status': 'unhealthy',
                    'message': str(e),
                    'duration_ms': 0,
                    'details': {}
                }
                overall_healthy = False
        
        results['status'] = 'healthy' if overall_healthy else 'unhealthy'
        return results
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity"""
        try:
            async with engine.connect() as conn:
                result = await conn.execute("SELECT 1 as test")
                row = result.fetchone()
                
                if row and row[0] == 1:
                    return {
                        'healthy': True,
                        'message': 'Database connection successful'
                    }
                else:
                    return {
                        'healthy': False,
                        'message': 'Database query returned unexpected result'
                    }
                    
        except Exception as e:
            return {
                'healthy': False,
                'message': f'Database connection failed: {str(e)}'
            }
    
    async def _check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity"""
        try:
            await redis_client.ping()
            return {
                'healthy': True,
                'message': 'Redis connection successful'
            }
        except Exception as e:
            return {
                'healthy': False,
                'message': f'Redis connection failed: {str(e)}'
            }
    
    async def _check_supabase(self) -> Dict[str, Any]:
        """Check Supabase API connectivity"""
        try:
            from app.core.database import supabase_client
            client = supabase_client.get_client()
            
            # Simple query to test connection
            response = client.table('organizations').select('id').limit(1).execute()
            
            return {
                'healthy': True,
                'message': 'Supabase API connection successful',
                'details': {
                    'response_count': len(response.data)
                }
            }
        except Exception as e:
            return {
                'healthy': False,
                'message': f'Supabase connection failed: {str(e)}'
            }
    
    async def _check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space"""
        try:
            import shutil
            
            total, used, free = shutil.disk_usage('/')
            free_percent = (free / total) * 100
            
            # Alert if less than 10% free space
            healthy = free_percent > 10
            
            return {
                'healthy': healthy,
                'message': f'Disk space: {free_percent:.1f}% free',
                'details': {
                    'total_gb': round(total / (1024**3), 2),
                    'used_gb': round(used / (1024**3), 2),
                    'free_gb': round(free / (1024**3), 2),
                    'free_percent': round(free_percent, 1)
                }
            }
        except Exception as e:
            return {
                'healthy': False,
                'message': f'Disk space check failed: {str(e)}'
            }
    
    async def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage"""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            available_percent = memory.available / memory.total * 100
            
            # Alert if less than 10% memory available
            healthy = available_percent > 10
            
            return {
                'healthy': healthy,
                'message': f'Memory: {available_percent:.1f}% available',
                'details': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'available_percent': round(available_percent, 1)
                }
            }
        except Exception as e:
            return {
                'healthy': False,
                'message': f'Memory check failed: {str(e)}'
            }

# Global health checker instance
health_checker = HealthChecker()
```

---

## 🔒 Security Configuration

### Authentication & Authorization

#### `app/core/security.py`
```python
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.core.database import supabase_client
import logging

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Bearer token authentication
security = HTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Try Supabase auth first
        supabase = supabase_client.get_client()
        user_response = supabase.auth.get_user(credentials.credentials)
        
        if user_response and user_response.user:
            return user_response.user
        
        # Fallback to custom JWT
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        # Get user from database
        user = await get_user_by_id(user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return user
        
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_user_by_id(user_id: str):
    """Get user by ID from Supabase"""
    try:
        supabase = supabase_client.get_client()
        response = supabase.from_('auth.users').select('*').eq('id', user_id).single().execute()
        return response.data if response.data else None
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {e}")
        return None

class RoleChecker:
    """Role-based access control"""
    
    def __init__(self, allowed_roles: list):
        self.allowed_roles = allowed_roles
    
    def __call__(self, current_user=Depends(get_current_user)):
        user_role = getattr(current_user, 'role', 'user')
        
        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return current_user

# Role-based dependency factories
require_admin = RoleChecker(['admin'])
require_manager = RoleChecker(['admin', 'manager'])
require_user = RoleChecker(['admin', 'manager', 'user'])
```

---

## 🚀 Deployment Instructions

### Step-by-Step Deployment Guide

#### 1. Hetzner Server Setup (10 minutes)
```bash
# 1. Create Hetzner Cloud server
# - Go to https://console.hetzner.cloud/projects
# - Create new project: "devsecure-production"
# - Add server: CPX51 (8 vCPUs, 16GB RAM, €29.90/month)
# - Choose Ubuntu 22.04 image
# - Add SSH key
# - Location: Nuremberg (nbg1)

# 2. Connect to server
ssh root@YOUR_SERVER_IP

# 3. Run setup script
curl -fsSL https://raw.githubusercontent.com/quadriconsulting/devsecure/main/deploy/setup_hetzner.sh | bash

# 4. Reboot to apply all changes
reboot
```

#### 2. Supabase Setup (15 minutes)
```bash
# 1. Create Supabase project
# - Go to https://supabase.com/dashboard
# - Create new project: "devsecure-production"
# - Choose region: Europe (eu-central-1)
# - Save credentials securely

# 2. Database setup
# Execute the SQL schemas from this document in Supabase SQL editor

# 3. Configure RLS policies
# Execute all RLS policies from the database section

# 4. Enable real-time subscriptions
# Execute real-time configuration commands

# 5. Configure authentication
# - Enable email/password auth
# - Set up email templates
# - Configure redirect URLs
```

#### 3. Environment Configuration (5 minutes)
```bash
# 1. SSH back to server
ssh root@YOUR_SERVER_IP

# 2. Configure environment
cd /opt/devsecure
cp .env.template .env

# 3. Edit environment file
nano .env

# Add your actual values:
# - Supabase URL and keys
# - GitHub App credentials  
# - OpenAI API key
# - Redis password
# - Secret keys
```

#### 4. Application Deployment (10 minutes)
```bash
# 1. Start the application
docker compose -f docker-compose.prod.yml up -d

# 2. Run database migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# 3. Check application health
curl http://localhost:8000/health

# 4. View logs
docker compose -f docker-compose.prod.yml logs -f api

# 5. Setup SSL certificates
sudo certbot --nginx -d api.devsecure.io -d app.devsecure.io
```

#### 5. DNS Configuration (5 minutes)
```bash
# Configure your domain DNS records:
# A record: api.devsecure.io -> YOUR_SERVER_IP
# A record: app.devsecure.io -> YOUR_SERVER_IP
# CNAME: www.devsecure.io -> app.devsecure.io
```

#### 6. Final Verification (5 minutes)
```bash
# 1. Test API endpoints
curl https://api.devsecure.io/health
curl https://api.devsecure.io/api/v1/health

# 2. Test WebSocket connections
# Use browser dev tools to test WebSocket connection

# 3. Monitor logs
tail -f /opt/devsecure/logs/*.log

# 4. Test auto-restart
systemctl status devsecure
```

### Total Deployment Time: ~50 minutes
### Monthly Infrastructure Cost: ~€35 ($38)

---

## 📋 Implementation Checklist

### Phase 1: Infrastructure Setup ✅
- [ ] Hetzner Cloud server provisioned
- [ ] Docker and Docker Compose installed
- [ ] Nginx reverse proxy configured
- [ ] SSL certificates obtained
- [ ] Supabase project created
- [ ] Database schema deployed
- [ ] RLS policies configured

### Phase 2: Backend Implementation ✅
- [ ] FastAPI application structure
- [ ] SQLAlchemy models defined
- [ ] Pydantic schemas created
- [ ] API routes implemented
- [ ] Authentication system
- [ ] Background task processing
- [ ] Scanning engine integration

### Phase 3: Security Scanners ✅
- [ ] SAST scanner (Semgrep)
- [ ] SCA scanner (dependencies)
- [ ] Secrets scanner (patterns)
- [ ] IaC scanner (Terraform/CloudFormation)
- [ ] Container scanner (Docker)

### Phase 4: Auto-Fix Engine ✅
- [ ] Pattern-based fixes
- [ ] AI-powered fix generation
- [ ] Fix validation logic
- [ ] GitHub integration
- [ ] PR creation automation

### Phase 5: Monitoring & Observability ✅
- [ ] Health check endpoints
- [ ] Prometheus metrics
- [ ] Structured logging
- [ ] Error tracking (Sentry)
- [ ] Performance monitoring

### Phase 6: Testing & Quality ✅
- [ ] Unit tests (pytest)
- [ ] Integration tests
- [ ] API tests (FastAPI TestClient)
- [ ] Load testing
- [ ] Security testing

### Phase 7: CI/CD Pipeline ✅
- [ ] GitHub Actions workflow
- [ ] Automated testing
- [ ] Docker image building
- [ ] Deployment automation
- [ ] Rollback procedures

---

## 🎯 Expected Performance Metrics

### Scan Performance
- **SAST Scan**: 1,000 LOC/second
- **SCA Scan**: 500 dependencies/second  
- **Secrets Scan**: 10,000 LOC/second
- **IaC Scan**: 100 files/second
- **Container Scan**: 1 layer/second

### Auto-Fix Performance
- **Pattern-based fixes**: <100ms generation
- **AI-powered fixes**: <2s generation
- **Fix validation**: <50ms per fix
- **PR creation**: <5s end-to-end

### System Performance
- **API Response Time**: <200ms (95th percentile)
- **Database Queries**: <50ms average
- **Memory Usage**: <8GB under load
- **CPU Usage**: <70% under load
- **Uptime**: >99.9% availability

---

## 💰 Cost Analysis

### Infrastructure Costs (Monthly)
- **Hetzner CPX51**: €29.90 (~$32)
- **Supabase Pro**: $25
- **Domain & SSL**: $2
- **Monitoring (optional)**: $10
- **Total**: ~$69/month

### Operational Costs
- **OpenAI API**: ~$50/month (estimated)
- **GitHub App**: Free
- **External APIs**: ~$20/month
- **Total**: ~$70/month

### **Grand Total: ~$139/month**

### ROI Comparison
- **Our Solution**: $139/month infrastructure + $30k/year software = $31.7k/year
- **Checkmarx**: $100k+/year
- **Aikido**: $50k/year

**Cost Savings: $18.3k - $68.3k per year vs competitors**

---

This comprehensive technical design document provides developers with everything needed to implement a production-ready DevSecure platform using FastAPI, Supabase, and Hetzner infrastructure. The architecture is designed for scalability, performance, and cost-effectiveness while maintaining competitive advantages through proprietary IP components.
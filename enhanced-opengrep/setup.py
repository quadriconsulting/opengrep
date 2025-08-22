#!/usr/bin/env python3
"""
Setup script for Enhanced Opengrep
AI-Powered Static Analysis with Auto-Fix & PR Integration
"""

from pathlib import Path
from setuptools import setup, find_packages

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r') as f:
        requirements = [
            line.strip() 
            for line in f.readlines() 
            if line.strip() and not line.startswith('#') and not line.startswith('-')
        ]

setup(
    name="enhanced-opengrep",
    version="1.0.0",
    author="Enhanced Opengrep Contributors",
    author_email="security@example.com",
    description="AI-Powered Static Analysis with 80% Auto-Fix Coverage and Smart PR Management",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/enhanced-opengrep",
    project_urls={
        "Bug Reports": "https://github.com/your-org/enhanced-opengrep/issues",
        "Source": "https://github.com/your-org/enhanced-opengrep",
        "Documentation": "https://enhanced-opengrep.readthedocs.io/",
    },
    
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology", 
        "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Utilities",
    ],
    
    python_requires=">=3.8",
    install_requires=requirements,
    
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.19.0",
            "pytest-mock>=3.8.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=0.18.0",
        ],
        "monitoring": [
            "prometheus-client>=0.15.0",
            "grafana-api>=1.0.3",
        ],
    },
    
    entry_points={
        "console_scripts": [
            "enhanced-opengrep=enhanced_opengrep_main:main",
            "eogrep=enhanced_opengrep_main:main",
        ],
    },
    
    include_package_data=True,
    package_data={
        "enhanced-opengrep": [
            "config/*.json",
            "config/*.yaml",
            "templates/*.md",
            "templates/*.txt",
        ],
    },
    
    zip_safe=False,
    
    keywords=[
        "security", 
        "static-analysis", 
        "vulnerability-scanner",
        "auto-fix", 
        "ai-powered", 
        "pull-requests",
        "devsecops",
        "sast",
        "code-analysis"
    ],
)
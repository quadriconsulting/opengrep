#!/usr/bin/env python3
"""
Setup script for Enhanced Opengrep SAST Tool
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="enhanced-opengrep-sast",
    version="1.0.0",
    description="Enhanced Opengrep SAST Tool with AI-Powered Auto-Fix and PR Automation",
    long_description=read_file("README.md") if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AI Security Expert",
    author_email="security@example.com",
    url="https://github.com/quadriconsulting/enhanced-opengrep",
    
    # Package configuration
    packages=find_packages(),
    py_modules=["enhanced_autofix_sast"],
    
    # Dependencies
    install_requires=read_requirements(),
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Entry points
    entry_points={
        "console_scripts": [
            "enhanced-opengrep=enhanced_autofix_sast:main",
            "eogrep=enhanced_autofix_sast:main",
        ],
    },
    
    # Package data
    package_data={
        "": [
            "config.yaml",
            "enhanced_fix_patterns.json",
            "*.md",
            "*.txt",
        ],
    },
    
    # Classifiers
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
    ],
    
    # Keywords
    keywords="security sast static-analysis vulnerability ai autofix automation",
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/quadriconsulting/enhanced-opengrep/issues",
        "Source": "https://github.com/quadriconsulting/enhanced-opengrep",
        "Documentation": "https://github.com/quadriconsulting/enhanced-opengrep/wiki",
    },
    
    # Additional metadata
    zip_safe=False,
    include_package_data=True,
)
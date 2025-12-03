"""
setup.py - Alternative setup for ATHF package

This file provides backward compatibility for older pip versions.
Modern installations should use pyproject.toml with PEP 621.
"""
from setuptools import setup

# All configuration is in pyproject.toml
# This file exists only for backward compatibility
if __name__ == "__main__":
    setup()

"""Behave environment configuration."""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def before_all(context):
    """Run before all tests."""
    # Set test environment
    os.environ['TESTING'] = 'true'
    os.environ['LOG_LEVEL'] = 'ERROR'

    # Create temp directory for test artifacts
    context.temp_dir = tempfile.mkdtemp(prefix='scanner_test_')
    print(f"Test temp directory: {context.temp_dir}")


def after_all(context):
    """Run after all tests."""
    # Cleanup temp directory
    if hasattr(context, 'temp_dir') and Path(context.temp_dir).exists():
        shutil.rmtree(context.temp_dir)

    # Clean environment
    os.environ.pop('TESTING', None)
    os.environ.pop('LOG_LEVEL', None)


def before_scenario(context, scenario):
    """Run before each scenario."""
    # Reset any scenario-specific state
    context.test_files = []
    context.results = {}
    context.exports = {}


def after_scenario(context, scenario):
    """Run after each scenario."""
    # Cleanup test files
    if hasattr(context, 'test_dir'):
        if Path(context.test_dir).exists():
            shutil.rmtree(context.test_dir)

    # Clean up any scenario-specific resources
    if hasattr(context, 'config_file'):
        try:
            os.unlink(context.config_file.name)
        except:
            pass


def before_feature(context, feature):
    """Run before each feature."""
    print(f"\n{'='*60}")
    print(f"Feature: {feature.name}")
    print(f"{'='*60}")


def after_feature(context, feature):
    """Run after each feature."""
    print(f"Feature {feature.name} completed")
    print(f"Scenarios: {len(feature.scenarios)}")
    print(f"Passed: {sum(1 for s in feature.scenarios if s.status == 'passed')}")
    print(f"Failed: {sum(1 for s in feature.scenarios if s.status == 'failed')}")

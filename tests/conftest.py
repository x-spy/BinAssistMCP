"""Collect tests without executing Binary Ninja's plugin entry point."""

from pathlib import Path

import pytest


def pytest_collection_modifyitems(items):
    root = Path(__file__).resolve().parents[1]
    for item in items:
        for collector in item.listchain():
            if isinstance(collector, pytest.Package) and collector.path.resolve() == root:
                # Package.setup imports root/__init__.py for xunit setup hooks.
                # Here that file registers UI callbacks and starts a live server;
                # neither is part of testing the src package in isolated processes.
                collector.setup = lambda: None

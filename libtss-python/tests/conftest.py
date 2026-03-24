"""Pytest configuration: ensure libtss package is importable."""

import os
import sys

# Add the libtss-python directory to sys.path so imports work from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sys
import os
import pytest

# Insert project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# This configuration file is automatically loaded by pytest
# It helps setting up the environment for all tests

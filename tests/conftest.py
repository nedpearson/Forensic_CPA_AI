import os
import pytest

# Ensure all tests run with the test database, not the live SQLite database
os.environ['TESTING'] = 'true'

import os

# Ensure all tests run with the test database, not the live SQLite database
os.environ['TESTING'] = 'true'

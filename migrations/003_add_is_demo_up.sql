-- Add is_demo flag to users table
ALTER TABLE users ADD COLUMN is_demo INTEGER DEFAULT 0;

-- Optionally, mark our specific demo email if it exists
UPDATE users SET is_demo = 1 WHERE email = 'demo@forensiccpa.ai';

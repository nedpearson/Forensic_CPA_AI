-- 002_remove_unique_constraints.sql
-- Remove UNIQUE constraint from categories.name to support multi-tenancy correctly.

CREATE TABLE categories_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    parent_category TEXT,
    category_type TEXT,
    color TEXT DEFAULT '#6c757d',
    icon TEXT
);

INSERT INTO categories_new (id, user_id, name, parent_category, category_type, color, icon)
SELECT id, user_id, name, parent_category, category_type, color, icon FROM categories;

DROP TABLE categories;
ALTER TABLE categories_new RENAME TO categories;

-- Same for taxonomy_config if it had one
CREATE TABLE taxonomy_config_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category_type TEXT NOT NULL,
    severity TEXT DEFAULT 'low',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO taxonomy_config_new (id, user_id, name, description, category_type, severity, created_at)
SELECT id, user_id, name, description, category_type, severity, created_at FROM taxonomy_config;

DROP TABLE taxonomy_config;
ALTER TABLE taxonomy_config_new RENAME TO taxonomy_config;

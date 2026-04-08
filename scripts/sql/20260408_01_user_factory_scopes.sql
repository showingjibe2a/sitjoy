-- Row-level factory access scope mapping.
-- Assign accessible factories per user (non-admin users).
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS user_factory_scopes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    factory_id INT UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_user_factory_scope (user_id, factory_id),
    INDEX idx_user_factory_scope_user (user_id),
    INDEX idx_user_factory_scope_factory (factory_id),
    CONSTRAINT fk_ufs_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_ufs_factory FOREIGN KEY (factory_id)
        REFERENCES logistics_factories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Example assignments (uncomment and adjust IDs before running):
-- INSERT INTO user_factory_scopes (user_id, factory_id) VALUES
-- (12, 1),
-- (12, 3),
-- (18, 2)
-- ON DUPLICATE KEY UPDATE factory_id = VALUES(factory_id);

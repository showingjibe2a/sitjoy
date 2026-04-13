-- Add contract and history fields for factory_wip_inventory

CREATE TABLE IF NOT EXISTS factory_contracts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    contract_no VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE factory_wip_inventory
    ADD COLUMN IF NOT EXISTS contract_id INT UNSIGNED NULL AFTER factory_id,
    ADD COLUMN IF NOT EXISTS initial_expected_completion_date DATE NULL AFTER expected_completion_date,
    ADD COLUMN IF NOT EXISTS update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER updated_at;

SET @idx_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_wip_inventory'
      AND index_name = 'idx_fwi_contract_id'
);
SET @idx_sql := IF(@idx_exists = 0,
    'ALTER TABLE factory_wip_inventory ADD INDEX idx_fwi_contract_id (contract_id)',
    'SELECT 1');
PREPARE stmt_idx FROM @idx_sql;
EXECUTE stmt_idx;
DEALLOCATE PREPARE stmt_idx;

SET @fk_exists := (
    SELECT COUNT(1)
    FROM information_schema.table_constraints
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_wip_inventory'
      AND constraint_type = 'FOREIGN KEY'
      AND constraint_name = 'fk_fwi_contract'
);
SET @fk_sql := IF(@fk_exists = 0,
    'ALTER TABLE factory_wip_inventory ADD CONSTRAINT fk_fwi_contract FOREIGN KEY (contract_id) REFERENCES factory_contracts(id) ON DELETE SET NULL',
    'SELECT 1');
PREPARE stmt_fk FROM @fk_sql;
EXECUTE stmt_fk;
DEALLOCATE PREPARE stmt_fk;

UPDATE factory_wip_inventory
SET initial_expected_completion_date = COALESCE(initial_expected_completion_date, expected_completion_date)
WHERE initial_expected_completion_date IS NULL;

UPDATE factory_wip_inventory
SET update_time = COALESCE(update_time, created_at)
WHERE update_time IS NULL;
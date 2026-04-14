-- Align factory WIP contract/order model:
-- 1) order_no and factory_id are maintained on factory_contracts (1:1 per factory)
-- 2) remove temporary standalone order number structures if they exist

ALTER TABLE factory_contracts
    ADD COLUMN IF NOT EXISTS order_no VARCHAR(128) NULL AFTER contract_no,
    ADD COLUMN IF NOT EXISTS factory_id INT UNSIGNED NULL AFTER id;

SET @idx_factory_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_contracts'
      AND index_name = 'idx_fc_factory_id'
);
SET @idx_factory_sql := IF(@idx_factory_exists = 0,
    'ALTER TABLE factory_contracts ADD INDEX idx_fc_factory_id (factory_id)',
    'SELECT 1');
PREPARE stmt_idx_factory FROM @idx_factory_sql;
EXECUTE stmt_idx_factory;
DEALLOCATE PREPARE stmt_idx_factory;

SET @fk_fc_factory_exists := (
    SELECT COUNT(1)
    FROM information_schema.table_constraints
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_contracts'
      AND constraint_type = 'FOREIGN KEY'
      AND constraint_name = 'fk_fc_factory'
);
SET @fk_fc_factory_sql := IF(@fk_fc_factory_exists = 0,
    'ALTER TABLE factory_contracts ADD CONSTRAINT fk_fc_factory FOREIGN KEY (factory_id) REFERENCES logistics_factories(id) ON DELETE RESTRICT',
    'SELECT 1');
PREPARE stmt_fk_fc_factory FROM @fk_fc_factory_sql;
EXECUTE stmt_fk_fc_factory;
DEALLOCATE PREPARE stmt_fk_fc_factory;

-- Drop legacy unique(contract_no) to allow per-factory uniqueness
SET @legacy_contract_unique_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_contracts'
      AND index_name = 'contract_no'
      AND non_unique = 0
);
SET @legacy_contract_unique_sql := IF(@legacy_contract_unique_exists > 0,
    'ALTER TABLE factory_contracts DROP INDEX contract_no',
    'SELECT 1');
PREPARE stmt_drop_legacy_contract_unique FROM @legacy_contract_unique_sql;
EXECUTE stmt_drop_legacy_contract_unique;
DEALLOCATE PREPARE stmt_drop_legacy_contract_unique;

SET @uq_fc_factory_contract_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_contracts'
      AND index_name = 'uq_fc_factory_contract'
      AND non_unique = 0
);
SET @uq_fc_factory_contract_sql := IF(@uq_fc_factory_contract_exists = 0,
    'ALTER TABLE factory_contracts ADD UNIQUE KEY uq_fc_factory_contract (factory_id, contract_no)',
    'SELECT 1');
PREPARE stmt_uq_fc_factory_contract FROM @uq_fc_factory_contract_sql;
EXECUTE stmt_uq_fc_factory_contract;
DEALLOCATE PREPARE stmt_uq_fc_factory_contract;

SET @uq_fc_factory_order_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_contracts'
      AND index_name = 'uq_fc_factory_order'
      AND non_unique = 0
);
SET @uq_fc_factory_order_sql := IF(@uq_fc_factory_order_exists = 0,
    'ALTER TABLE factory_contracts ADD UNIQUE KEY uq_fc_factory_order (factory_id, order_no)',
    'SELECT 1');
PREPARE stmt_uq_fc_factory_order FROM @uq_fc_factory_order_sql;
EXECUTE stmt_uq_fc_factory_order;
DEALLOCATE PREPARE stmt_uq_fc_factory_order;

-- Cleanup temporary structure from previous draft (if present)
SET @fk_fwi_order_no_exists := (
    SELECT COUNT(1)
    FROM information_schema.table_constraints
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_wip_inventory'
      AND constraint_type = 'FOREIGN KEY'
      AND constraint_name = 'fk_fwi_order_no'
);
SET @drop_fk_fwi_order_no_sql := IF(@fk_fwi_order_no_exists > 0,
    'ALTER TABLE factory_wip_inventory DROP FOREIGN KEY fk_fwi_order_no',
    'SELECT 1');
PREPARE stmt_drop_fk_fwi_order_no FROM @drop_fk_fwi_order_no_sql;
EXECUTE stmt_drop_fk_fwi_order_no;
DEALLOCATE PREPARE stmt_drop_fk_fwi_order_no;

SET @idx_fwi_order_no_exists := (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_wip_inventory'
      AND index_name = 'idx_fwi_order_no_id'
);
SET @drop_idx_fwi_order_no_sql := IF(@idx_fwi_order_no_exists > 0,
    'ALTER TABLE factory_wip_inventory DROP INDEX idx_fwi_order_no_id',
    'SELECT 1');
PREPARE stmt_drop_idx_fwi_order_no FROM @drop_idx_fwi_order_no_sql;
EXECUTE stmt_drop_idx_fwi_order_no;
DEALLOCATE PREPARE stmt_drop_idx_fwi_order_no;

SET @col_fwi_order_no_exists := (
    SELECT COUNT(1)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'factory_wip_inventory'
      AND column_name = 'order_no_id'
);
SET @drop_col_fwi_order_no_sql := IF(@col_fwi_order_no_exists > 0,
    'ALTER TABLE factory_wip_inventory DROP COLUMN order_no_id',
    'SELECT 1');
PREPARE stmt_drop_col_fwi_order_no FROM @drop_col_fwi_order_no_sql;
EXECUTE stmt_drop_col_fwi_order_no;
DEALLOCATE PREPARE stmt_drop_col_fwi_order_no;

DROP TABLE IF EXISTS factory_order_numbers;

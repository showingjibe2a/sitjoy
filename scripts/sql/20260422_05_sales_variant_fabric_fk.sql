-- Sales variant fabric: migrate from text to FK fabric_id
-- Generated: 2026-04-22
SET NAMES utf8mb4;

-- 1) Add fabric_id if missing
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sales_product_variants' AND COLUMN_NAME='fabric_id'
);
SET @sql := IF(@has_col=0,
  'ALTER TABLE sales_product_variants ADD COLUMN fabric_id INT UNSIGNED NULL AFTER spec_name',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) Backfill fabric_id from legacy v.fabric text (match fabric_code or fabric_name_en)
UPDATE sales_product_variants v
LEFT JOIN fabric_materials fm
  ON fm.fabric_code = TRIM(v.fabric)
  OR fm.fabric_name_en = TRIM(v.fabric)
SET v.fabric_id = COALESCE(v.fabric_id, fm.id)
WHERE (v.fabric_id IS NULL OR v.fabric_id=0) AND TRIM(IFNULL(v.fabric,'')) <> '';

-- 3) Add index + FK (optional but recommended)
SET @has_idx := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sales_product_variants' AND INDEX_NAME='idx_spv_fabric'
);
SET @sql := IF(@has_idx=0,
  'ALTER TABLE sales_product_variants ADD INDEX idx_spv_fabric (fabric_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add FK only if not exists (best-effort)
SET @fk := (
  SELECT CONSTRAINT_NAME
  FROM information_schema.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA=DATABASE()
    AND TABLE_NAME='sales_product_variants'
    AND COLUMN_NAME='fabric_id'
    AND REFERENCED_TABLE_NAME='fabric_materials'
  LIMIT 1
);
SET @sql := IF(@fk IS NULL OR @fk='',
  'ALTER TABLE sales_product_variants ADD CONSTRAINT fk_spv_fabric FOREIGN KEY (fabric_id) REFERENCES fabric_materials(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 4) (Optional) When fully migrated, you may drop legacy text column `fabric`
-- ALTER TABLE sales_product_variants DROP COLUMN fabric;


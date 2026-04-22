-- Move sales main image mapping key from sales_product_id to variant_id
-- Generated: 2026-04-22
SET NAMES utf8mb4;

-- 1) Ensure sku_image_mappings.variant_id exists (added earlier in 20260417_01, but keep idempotent)
SET @has_variant_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND COLUMN_NAME='variant_id'
);
SET @sql := IF(@has_variant_col=0,
  'ALTER TABLE sku_image_mappings ADD COLUMN variant_id INT UNSIGNED NULL AFTER sales_product_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) Backfill variant_id from sales_products
UPDATE sku_image_mappings sim
JOIN sales_products sp ON sp.id = sim.sales_product_id
SET sim.variant_id = sp.variant_id
WHERE (sim.variant_id IS NULL OR sim.variant_id=0) AND sp.variant_id IS NOT NULL;

-- 3) Add unique key on (variant_id, image_asset_id) for variant-level relation
SET @has_uniq_variant := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND INDEX_NAME='uniq_sim_variant_asset'
);
SET @sql := IF(@has_uniq_variant=0,
  'ALTER TABLE sku_image_mappings ADD UNIQUE KEY uniq_sim_variant_asset (variant_id, image_asset_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 4) Helpful index for reads
SET @has_idx_variant_sort := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND INDEX_NAME='idx_sim_variant_sort'
);
SET @sql := IF(@has_idx_variant_sort=0,
  'ALTER TABLE sku_image_mappings ADD INDEX idx_sim_variant_sort (variant_id, is_deprecated, group_sort, sort_order, id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 5) Optional clean-up (run manually after verifying all code uses variant_id):
-- Dropping sales_product_id requires dropping related FK/indexes first.
-- Use the following idempotent block (copy & run when you're ready):
-- Drop FK referencing sales_products (if present)
SET @fk := (
  SELECT CONSTRAINT_NAME
  FROM information_schema.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA=DATABASE()
    AND TABLE_NAME='sku_image_mappings'
    AND COLUMN_NAME='sales_product_id'
    AND REFERENCED_TABLE_NAME='sales_products'
  LIMIT 1
);
SET @sql := IF(@fk IS NULL OR @fk='', 'SELECT 1', CONCAT('ALTER TABLE sku_image_mappings DROP FOREIGN KEY ', @fk));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Drop indexes that still include sales_product_id (common names)
SET @has_idx_sort := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND INDEX_NAME='idx_sku_images_sort'
);
SET @sql := IF(@has_idx_sort=0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP INDEX idx_sku_images_sort');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_product := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND INDEX_NAME='idx_sku_images_product'
);
SET @sql := IF(@has_idx_product=0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP INDEX idx_sku_images_product');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Drop old unique key on sales_product_id (if present)
SET @has_uniq_old := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND INDEX_NAME='uniq_sku_image_mapping'
);
SET @sql := IF(@has_uniq_old=0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP INDEX uniq_sku_image_mapping');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Finally drop the column
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND COLUMN_NAME='sales_product_id'
);
SET @sql := IF(@has_col=0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP COLUMN sales_product_id');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;


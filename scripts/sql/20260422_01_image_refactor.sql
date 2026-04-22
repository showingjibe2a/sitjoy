-- Image refactor (sales main images + fabric images)
-- Generated: 2026-04-22
-- Notes:
-- - This migration is designed to be idempotent and backward compatible.
-- - Do NOT drop old columns/tables until all code paths are switched and data is verified.
SET NAMES utf8mb4;

-- 1) Image type normalization / rename
UPDATE image_types SET name='Swatch' WHERE name IN ('主图·Swatch', 'swatch', 'SWATCH');
UPDATE image_types SET name='文字卖点图' WHERE name IN ('主图·卖点', '图文卖点', '图文卖点图');

-- Ensure common types exist
INSERT INTO image_types (name, sort_order, is_enabled)
SELECT 'Swatch', 15, 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='Swatch');

INSERT INTO image_types (name, sort_order, is_enabled)
SELECT '文字卖点图', 40, 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='文字卖点图');

-- 2) sku_image_mappings: add deprecated flag + group sort
SET @has_sim_dep := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND COLUMN_NAME='is_deprecated'
);
SET @sql := IF(@has_sim_dep=0,
  'ALTER TABLE sku_image_mappings ADD COLUMN is_deprecated TINYINT(1) NOT NULL DEFAULT 0 AFTER sort_order',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_sim_group := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sku_image_mappings' AND COLUMN_NAME='group_sort'
);
SET @sql := IF(@has_sim_group=0,
  'ALTER TABLE sku_image_mappings ADD COLUMN group_sort INT UNSIGNED NOT NULL DEFAULT 100 AFTER is_deprecated',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Backfill group_sort to current sort_order for stable ordering
UPDATE sku_image_mappings
SET group_sort = IFNULL(group_sort, sort_order)
WHERE group_sort IS NULL OR group_sort = 100;

-- 3) Fabric images: new mapping table to image_assets (do not drop old fabric_images yet)
CREATE TABLE IF NOT EXISTS fabric_image_mappings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  fabric_id INT UNSIGNED NOT NULL,
  image_asset_id BIGINT UNSIGNED NOT NULL,
  remark VARCHAR(50) NULL DEFAULT NULL,
  sort_order INT UNSIGNED NOT NULL DEFAULT 0,
  is_deprecated TINYINT(1) NOT NULL DEFAULT 0,
  created_by INT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_fabric_image (fabric_id, image_asset_id),
  INDEX idx_fim_fabric_sort (fabric_id, is_deprecated, sort_order, id),
  INDEX idx_fim_asset (image_asset_id),
  CONSTRAINT fk_fim_fabric FOREIGN KEY (fabric_id) REFERENCES fabric_materials(id) ON DELETE CASCADE,
  CONSTRAINT fk_fim_asset FOREIGN KEY (image_asset_id) REFERENCES image_assets(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4) Optional: keep created_by populated when possible (no-op if columns missing)
-- (Handled in application code for new rows.)


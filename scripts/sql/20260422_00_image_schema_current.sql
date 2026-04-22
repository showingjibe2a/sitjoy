-- Image/Fabric/Sales main-image schema baseline (current)
-- Generated: 2026-04-22
-- Purpose: make runtime code compatible with the CURRENT schema in this repo:
-- - image metadata lives on image_assets (description, image_type_id, is_deprecated)
-- - sku_image_mappings binds images to sales_product_variants via variant_id (preferred)
-- - fabric_image_mappings binds images to fabric_materials
-- - legacy fabric_images table and redundant mapping columns can be dropped
--
-- Notes:
-- - This script is designed to be idempotent (safe to run multiple times).
-- - It does NOT attempt to recreate the whole database, only the image-related schema.
SET NAMES utf8mb4;

-- ----------------------------
-- image_assets (central image registry)
-- ----------------------------
CREATE TABLE IF NOT EXISTS image_assets (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  sha256 CHAR(64) NOT NULL,
  storage_path VARCHAR(500) NOT NULL,
  description VARCHAR(500) NULL,
  image_type_id INT UNSIGNED NULL,
  is_deprecated TINYINT(1) NOT NULL DEFAULT 0,
  created_by INT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_image_assets_sha256 (sha256),
  INDEX idx_image_assets_type (image_type_id),
  INDEX idx_image_assets_deprecated (is_deprecated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional legacy column; keep if you still have it, but code no longer depends on it.
-- (If you want to remove it, do it after verifying no other modules depend on it.)
-- ALTER TABLE image_assets DROP COLUMN original_filename;

-- ----------------------------
-- image_types (supports applies_* scope flags)
-- ----------------------------
CREATE TABLE IF NOT EXISTS image_types (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  applies_fabric TINYINT(1) NOT NULL DEFAULT 1,
  applies_sales TINYINT(1) NOT NULL DEFAULT 1,
  applies_aplus TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_image_types_name (name),
  INDEX idx_image_types_enabled (is_enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- sku_image_mappings (sales variant <-> image_assets)
-- ----------------------------
CREATE TABLE IF NOT EXISTS sku_image_mappings (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  variant_id INT UNSIGNED NOT NULL,
  image_asset_id INT UNSIGNED NOT NULL,
  sort_order INT UNSIGNED NOT NULL DEFAULT 1,
  created_by INT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_sim_variant_asset (variant_id, image_asset_id),
  INDEX idx_sim_variant_sort (variant_id, sort_order, id),
  INDEX idx_sim_asset (image_asset_id),
  CONSTRAINT fk_sim_asset FOREIGN KEY (image_asset_id) REFERENCES image_assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Drop legacy columns in sku_image_mappings if they still exist
-- (image_type_id/is_deprecated/group_sort/sales_product_id are deprecated)
SET @db := DATABASE();
SET @t := 'sku_image_mappings';
-- sales_product_id
SET @c := 'sales_product_id';
SET @sql := (
  SELECT IF(COUNT(*)>0, CONCAT('ALTER TABLE ', @t, ' DROP COLUMN ', @c), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- image_type_id
SET @c := 'image_type_id';
SET @sql := (
  SELECT IF(COUNT(*)>0, CONCAT('ALTER TABLE ', @t, ' DROP COLUMN ', @c), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- is_deprecated
SET @c := 'is_deprecated';
SET @sql := (
  SELECT IF(COUNT(*)>0, CONCAT('ALTER TABLE ', @t, ' DROP COLUMN ', @c), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- group_sort
SET @c := 'group_sort';
SET @sql := (
  SELECT IF(COUNT(*)>0, CONCAT('ALTER TABLE ', @t, ' DROP COLUMN ', @c), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ----------------------------
-- fabric_image_mappings (fabric <-> image_assets)
-- ----------------------------
CREATE TABLE IF NOT EXISTS fabric_image_mappings (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  fabric_id INT UNSIGNED NOT NULL,
  image_asset_id INT UNSIGNED NOT NULL,
  sort_order INT UNSIGNED NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_fim_fabric_asset (fabric_id, image_asset_id),
  INDEX idx_fim_fabric_sort (fabric_id, sort_order, id),
  INDEX idx_fim_asset (image_asset_id),
  CONSTRAINT fk_fim_asset FOREIGN KEY (image_asset_id) REFERENCES image_assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- sales_product_variants: enforce fabric_id (and optionally remove legacy fabric text)
-- ----------------------------
-- Ensure fabric_id exists
SET @t := 'sales_product_variants';
SET @c := 'fabric_id';
SET @sql := (
  SELECT IF(COUNT(*)=0, CONCAT('ALTER TABLE ', @t, ' ADD COLUMN fabric_id INT UNSIGNED NULL'), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Drop legacy fabric text column if it exists
SET @c := 'fabric';
SET @sql := (
  SELECT IF(COUNT(*)>0, CONCAT('ALTER TABLE ', @t, ' DROP COLUMN ', @c), 'SELECT 1')
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ----------------------------
-- Drop legacy fabric_images table (already migrated to fabric_image_mappings + image_assets)
-- ----------------------------
DROP TABLE IF EXISTS fabric_images;


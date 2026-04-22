-- Add scope flags to image_types so each type can be limited by module usage
SET NAMES utf8mb4;

SET @has_fabric := (
  SELECT COUNT(1)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_types' AND COLUMN_NAME = 'applies_fabric'
);
SET @sql := IF(@has_fabric = 0,
  'ALTER TABLE image_types ADD COLUMN applies_fabric TINYINT(1) NOT NULL DEFAULT 1 AFTER is_enabled',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_sales := (
  SELECT COUNT(1)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_types' AND COLUMN_NAME = 'applies_sales'
);
SET @sql := IF(@has_sales = 0,
  'ALTER TABLE image_types ADD COLUMN applies_sales TINYINT(1) NOT NULL DEFAULT 1 AFTER applies_fabric',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_aplus := (
  SELECT COUNT(1)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_types' AND COLUMN_NAME = 'applies_aplus'
);
SET @sql := IF(@has_aplus = 0,
  'ALTER TABLE image_types ADD COLUMN applies_aplus TINYINT(1) NOT NULL DEFAULT 1 AFTER applies_sales',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Existing rows default to 1 so legacy behavior remains unchanged.
UPDATE image_types
SET applies_fabric = COALESCE(applies_fabric, 1),
    applies_sales = COALESCE(applies_sales, 1),
    applies_aplus = COALESCE(applies_aplus, 1);

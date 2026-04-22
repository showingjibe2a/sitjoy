-- Drop unused original_filename column from image_assets table
-- original_filename is redundant since original names aren't needed after upload
-- This simplifies the image_assets schema and reduces metadata noise

SET NAMES utf8mb4;

-- Idempotent column drop check
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = 'original_filename'
);

SET @sql := IF(@has_col > 0,
  'ALTER TABLE image_assets DROP COLUMN original_filename',
  'SELECT 1 AS "original_filename already dropped"'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Verify column is gone
SELECT IF(
  (SELECT COUNT(1) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = 'original_filename') = 0,
  'SUCCESS: original_filename column dropped',
  'ERROR: original_filename column still exists'
) AS migration_status;

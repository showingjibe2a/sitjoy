-- Center image metadata on image_assets; slim sku/fabric mappings; drop legacy fabric_images.
-- Run once on a backup. Idempotent where marked.
SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
-- 1) image_assets: add type + deprecated on the asset row
-- ---------------------------------------------------------------------------
SET @has_ia_tid := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = 'image_type_id'
);
SET @sql := IF(@has_ia_tid = 0,
  'ALTER TABLE image_assets ADD COLUMN image_type_id INT UNSIGNED NULL AFTER original_filename',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_ia_dep := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = 'is_deprecated'
);
SET @sql := IF(@has_ia_dep = 0,
  'ALTER TABLE image_assets ADD COLUMN is_deprecated TINYINT(1) NOT NULL DEFAULT 0 AFTER image_type_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Backfill image_assets.image_type_id / is_deprecated from sku_image_mappings (per-asset aggregate)
SET @has_sim_tid := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'image_type_id'
);
SET @has_sim_dep := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'is_deprecated'
);

SET @sql := IF(@has_sim_tid > 0,
  'UPDATE image_assets ia JOIN (SELECT image_asset_id, MIN(image_type_id) AS tid FROM sku_image_mappings WHERE image_type_id IS NOT NULL AND image_type_id>0 GROUP BY image_asset_id) x ON x.image_asset_id=ia.id SET ia.image_type_id = COALESCE(ia.image_type_id, x.tid)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(@has_sim_dep > 0,
  'UPDATE image_assets ia JOIN (SELECT image_asset_id, MAX(is_deprecated) AS dep FROM sku_image_mappings GROUP BY image_asset_id) x ON x.image_asset_id=ia.id SET ia.is_deprecated = GREATEST(COALESCE(ia.is_deprecated,0), COALESCE(x.dep,0))',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Backfill from fabric_image_mappings.remark (legacy text type) when image_types matches by name
SET @has_fim_remark := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_image_mappings' AND COLUMN_NAME = 'remark'
);
SET @sql := IF(@has_fim_remark > 0,
  'UPDATE image_assets ia INNER JOIN fabric_image_mappings fim ON fim.image_asset_id=ia.id INNER JOIN image_types it ON it.name = TRIM(fim.remark) SET ia.image_type_id = COALESCE(ia.image_type_id, it.id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- (Optional) Add FK image_assets.image_type_id -> image_types in a separate step if desired.

-- ---------------------------------------------------------------------------
-- 2) sku_image_mappings: drop per-mapping type / deprecated / group_sort
-- ---------------------------------------------------------------------------
SET @fk := (
  SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings'
    AND COLUMN_NAME = 'image_type_id' AND REFERENCED_TABLE_NAME = 'image_types'
  LIMIT 1
);
SET @sql := IF(@fk IS NULL OR @fk = '', 'SELECT 1', CONCAT('ALTER TABLE sku_image_mappings DROP FOREIGN KEY ', @fk));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_type := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND INDEX_NAME = 'idx_sku_images_type'
);
SET @sql := IF(@has_idx_type = 0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP INDEX idx_sku_images_type');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_var_sort := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND INDEX_NAME = 'idx_sim_variant_sort'
);
SET @sql := IF(@has_idx_var_sort = 0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP INDEX idx_sim_variant_sort');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'image_type_id'
);
SET @sql := IF(@has_col = 0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP COLUMN image_type_id');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'is_deprecated'
);
SET @sql := IF(@has_col = 0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP COLUMN is_deprecated');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'group_sort'
);
SET @sql := IF(@has_col = 0, 'SELECT 1', 'ALTER TABLE sku_image_mappings DROP COLUMN group_sort');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_var_sort2 := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND INDEX_NAME = 'idx_sim_variant_sort'
);
SET @has_vcol := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sku_image_mappings' AND COLUMN_NAME = 'variant_id'
);
SET @sql := IF(@has_idx_var_sort2 > 0 OR @has_vcol = 0, 'SELECT 1',
  'ALTER TABLE sku_image_mappings ADD INDEX idx_sim_variant_sort (variant_id, sort_order, id)'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 3) fabric_image_mappings: drop remark + is_deprecated (type lives on image_assets)
-- ---------------------------------------------------------------------------
SET @has_idx_fim := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_image_mappings' AND INDEX_NAME = 'idx_fim_fabric_sort'
);
SET @sql := IF(@has_idx_fim = 0, 'SELECT 1', 'ALTER TABLE fabric_image_mappings DROP INDEX idx_fim_fabric_sort');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_image_mappings' AND COLUMN_NAME = 'remark'
);
SET @sql := IF(@has_col = 0, 'SELECT 1', 'ALTER TABLE fabric_image_mappings DROP COLUMN remark');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_image_mappings' AND COLUMN_NAME = 'is_deprecated'
);
SET @sql := IF(@has_col = 0, 'SELECT 1', 'ALTER TABLE fabric_image_mappings DROP COLUMN is_deprecated');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_fim2 := (
  SELECT COUNT(1) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_image_mappings' AND INDEX_NAME = 'idx_fim_fabric_sort'
);
SET @sql := IF(@has_idx_fim2 = 0,
  'ALTER TABLE fabric_image_mappings ADD INDEX idx_fim_fabric_sort (fabric_id, sort_order, id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 4) image_assets: drop unused metadata columns
-- ---------------------------------------------------------------------------
SET @drops := 'file_ext,mime_type,file_size,width,height';
-- handled in application loop below via dynamic SQL is verbose; drop one-by-one:

SET @col := 'file_ext';
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = @col
);
SET @sql := IF(@has_col = 0, 'SELECT 1', CONCAT('ALTER TABLE image_assets DROP COLUMN ', @col));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := 'mime_type';
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = @col
);
SET @sql := IF(@has_col = 0, 'SELECT 1', CONCAT('ALTER TABLE image_assets DROP COLUMN ', @col));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := 'file_size';
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = @col
);
SET @sql := IF(@has_col = 0, 'SELECT 1', CONCAT('ALTER TABLE image_assets DROP COLUMN ', @col));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := 'width';
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = @col
);
SET @sql := IF(@has_col = 0, 'SELECT 1', CONCAT('ALTER TABLE image_assets DROP COLUMN ', @col));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := 'height';
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'image_assets' AND COLUMN_NAME = @col
);
SET @sql := IF(@has_col = 0, 'SELECT 1', CONCAT('ALTER TABLE image_assets DROP COLUMN ', @col));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- 5) Drop legacy fabric_images (post-migration only)
-- ---------------------------------------------------------------------------
SET @has_fi := (
  SELECT COUNT(1) FROM information_schema.TABLES
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fabric_images'
);
SET @sql := IF(@has_fi = 0, 'SELECT 1', 'DROP TABLE fabric_images');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

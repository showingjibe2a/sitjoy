-- Safely drop legacy sales_product_variants.fabric (text) by removing indexes referencing it first.
-- Generated: 2026-04-22
SET NAMES utf8mb4;

-- 1) Drop any indexes that reference column `fabric`
SET @tbl := 'sales_product_variants';
SET @col := 'fabric';

-- Build and run DROP INDEX statements for all indexes that include `fabric`
SELECT GROUP_CONCAT(CONCAT('ALTER TABLE ', @tbl, ' DROP INDEX `', s.INDEX_NAME, '`;') SEPARATOR ' ')
INTO @drop_sql
FROM (
  SELECT DISTINCT INDEX_NAME
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = @tbl
    AND COLUMN_NAME = @col
    AND INDEX_NAME <> 'PRIMARY'
) s;

SET @drop_sql := IF(@drop_sql IS NULL OR @drop_sql = '', 'SELECT 1;', @drop_sql);
PREPARE stmt FROM @drop_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) Drop the column (idempotent)
SET @has_col := (
  SELECT COUNT(1) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=@tbl AND COLUMN_NAME=@col
);
SET @sql := IF(@has_col=0, 'SELECT 1', CONCAT('ALTER TABLE ', @tbl, ' DROP COLUMN ', @col));
PREPARE stmt2 FROM @sql; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;


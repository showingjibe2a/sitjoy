-- Add required image dimensions to image_types
-- Generated: 2026-04-23
-- Idempotent: safe to run multiple times
SET NAMES utf8mb4;

SET @db := DATABASE();
SET @t := 'image_types';

-- required_width_px
SET @c := 'required_width_px';
SET @sql := (
  SELECT IF(
    COUNT(*)>0,
    'SELECT 1',
    CONCAT('ALTER TABLE ', @t, ' ADD COLUMN ', @c, ' INT NULL')
  )
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- required_height_px
SET @c := 'required_height_px';
SET @sql := (
  SELECT IF(
    COUNT(*)>0,
    'SELECT 1',
    CONCAT('ALTER TABLE ', @t, ' ADD COLUMN ', @c, ' INT NULL')
  )
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME=@c
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;


-- Image type <-> platform_types many-to-many mapping
-- Generated: 2026-04-23
-- Semantics:
-- - If an image_type has NO rows in this table -> it is "通用" (available for all platforms)
-- - If it has rows -> only available for those platform_types
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS image_type_platform_types (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  image_type_id INT UNSIGNED NOT NULL,
  platform_type_id INT UNSIGNED NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_itpt (image_type_id, platform_type_id),
  INDEX idx_itpt_type (image_type_id),
  INDEX idx_itpt_platform (platform_type_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


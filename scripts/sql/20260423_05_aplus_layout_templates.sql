-- A+ layout templates: bind image_type_id -> reusable layout_json
-- plus device applicability flags (mobile/desktop)
-- Generated: 2026-04-23
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS aplus_layout_templates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  image_type_id INT UNSIGNED NOT NULL,
  template_name VARCHAR(128) NOT NULL,
  applies_mobile TINYINT(1) NOT NULL DEFAULT 1,
  applies_desktop TINYINT(1) NOT NULL DEFAULT 1,
  layout_json LONGTEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_alt_type_name (image_type_id, template_name),
  INDEX idx_alt_type (image_type_id),
  INDEX idx_alt_mobile (applies_mobile),
  INDEX idx_alt_desktop (applies_desktop)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- aplus_versions references selected template (nullable)
ALTER TABLE aplus_versions ADD COLUMN layout_template_id BIGINT UNSIGNED NULL;


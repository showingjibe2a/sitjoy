-- A+ versions, assets binding, and layout schema
-- Generated: 2026-04-23
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS aplus_versions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  version_name VARCHAR(128) NOT NULL,
  platform_type_id INT UNSIGNED NOT NULL,
  sku_family_id INT UNSIGNED NOT NULL,
  created_by INT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_aplus_version (platform_type_id, sku_family_id, version_name),
  INDEX idx_aplus_platform (platform_type_id),
  INDEX idx_aplus_sku_family (sku_family_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aplus_version_assets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  aplus_version_id BIGINT UNSIGNED NOT NULL,
  image_asset_id INT UNSIGNED NOT NULL,
  sort_order INT UNSIGNED NOT NULL DEFAULT 1,
  role VARCHAR(32) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_apva_version_asset (aplus_version_id, image_asset_id),
  INDEX idx_apva_version_sort (aplus_version_id, sort_order, id),
  INDEX idx_apva_asset (image_asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aplus_version_layout (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  aplus_version_id BIGINT UNSIGNED NOT NULL,
  layout_json LONGTEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_apl_version (aplus_version_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


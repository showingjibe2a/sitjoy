-- Image asset + SKU relation schema
-- Generated: 2026-04-03
SET NAMES utf8mb4;

-- ----------------------------
-- Table: image_types
-- ----------------------------
CREATE TABLE IF NOT EXISTS image_types (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    sort_order INT UNSIGNED NOT NULL DEFAULT 100,
    is_enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_image_type_name (name),
    INDEX idx_image_type_enabled_sort (is_enabled, sort_order, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed common image types (idempotent)
INSERT INTO image_types (name, sort_order)
VALUES
    ('白底图', 10),
    ('场景图', 20),
    ('细节图', 30),
    ('图文卖点', 40)
ON DUPLICATE KEY UPDATE
    sort_order = VALUES(sort_order),
    is_enabled = 1;

-- ----------------------------
-- Table: image_assets
-- One physical file, one row. Deduplicate by sha256.
-- ----------------------------
CREATE TABLE IF NOT EXISTS image_assets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sha256 CHAR(64) NOT NULL,
    storage_path VARCHAR(512) NOT NULL COMMENT 'relative file path under resources',
    original_filename VARCHAR(255) NULL,
    file_ext VARCHAR(16) NULL,
    mime_type VARCHAR(64) NULL,
    file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    width INT UNSIGNED NULL,
    height INT UNSIGNED NULL,
    description VARCHAR(1000) NULL COMMENT 'image-level description only',
    created_by INT UNSIGNED NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_image_asset_sha256 (sha256),
    UNIQUE KEY uniq_image_asset_storage_path (storage_path),
    INDEX idx_image_asset_created_at (created_at),
    INDEX idx_image_asset_size (file_size)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sku_image_mappings
-- Relation between SKU and image assets, with ordering and image type.
-- sales_product_id keeps the relation keyed to sales_products.id for faster joins and referential integrity.
-- ----------------------------
CREATE TABLE IF NOT EXISTS sku_image_mappings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sales_product_id INT UNSIGNED NOT NULL,
    image_asset_id BIGINT UNSIGNED NOT NULL,
    image_type_id INT UNSIGNED NOT NULL,
    sort_order INT UNSIGNED NOT NULL DEFAULT 100,
    created_by INT UNSIGNED NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_sku_image_mapping (sales_product_id, image_asset_id),
    INDEX idx_sku_images_sort (sales_product_id, sort_order, id),
    INDEX idx_sku_images_type (image_type_id),
    INDEX idx_sku_images_asset (image_asset_id),
    INDEX idx_sku_images_product (sales_product_id),
    CONSTRAINT fk_sku_image_sales_product FOREIGN KEY (sales_product_id)
        REFERENCES sales_products(id) ON DELETE CASCADE,
    CONSTRAINT fk_sku_image_asset FOREIGN KEY (image_asset_id)
        REFERENCES image_assets(id) ON DELETE RESTRICT,
    CONSTRAINT fk_sku_image_type FOREIGN KEY (image_type_id)
        REFERENCES image_types(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

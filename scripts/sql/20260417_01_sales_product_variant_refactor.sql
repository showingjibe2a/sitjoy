-- Sales product refactor (phase 1, backward-compatible)
-- Generated: 2026-04-17
-- Goal:
-- 1) Introduce variant identity table: (sku_family_id, spec_name, fabric) unique.
-- 2) Support many platform SKUs -> one variant.
-- 3) Keep existing runtime compatible during transition.

SET NAMES utf8mb4;

-- 0) Pre-clean: fill missing shop_id from parent where possible
UPDATE sales_products sp
LEFT JOIN sales_parents p ON p.id = sp.parent_id
SET sp.shop_id = p.shop_id
WHERE sp.shop_id IS NULL AND p.shop_id IS NOT NULL;

-- 1) Variant master table (single source of truth for 货号+规格名称+面料)
CREATE TABLE IF NOT EXISTS sales_product_variants (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sku_family_id INT UNSIGNED NOT NULL,
    spec_name VARCHAR(255) NOT NULL,
    fabric VARCHAR(255) NOT NULL,
    sale_price_usd DECIMAL(10,2) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_spv_identity (sku_family_id, spec_name, fabric),
    INDEX idx_spv_sku_family (sku_family_id),
    CONSTRAINT fk_spv_sku_family FOREIGN KEY (sku_family_id)
        REFERENCES product_families(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) Backfill variants from existing sales_products
INSERT INTO sales_product_variants (sku_family_id, spec_name, fabric, sale_price_usd)
SELECT
    sp.sku_family_id,
    TRIM(COALESCE(sp.spec_name, '')) AS spec_name,
    TRIM(COALESCE(sp.fabric, '')) AS fabric,
    MAX(sp.sale_price_usd) AS sale_price_usd
FROM sales_products sp
WHERE sp.sku_family_id IS NOT NULL
GROUP BY sp.sku_family_id, TRIM(COALESCE(sp.spec_name, '')), TRIM(COALESCE(sp.fabric, ''))
ON DUPLICATE KEY UPDATE
    sale_price_usd = COALESCE(VALUES(sale_price_usd), sales_product_variants.sale_price_usd);

-- 3) Add variant_id into sales_products
SET @has_variant_col := (
    SELECT COUNT(1)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND COLUMN_NAME = 'variant_id'
);
SET @sql := IF(@has_variant_col = 0,
    'ALTER TABLE sales_products ADD COLUMN variant_id INT UNSIGNED NULL AFTER sku_family_id',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 4) Backfill sales_products.variant_id by identity mapping
UPDATE sales_products sp
JOIN sales_product_variants v
  ON v.sku_family_id = sp.sku_family_id
 AND v.spec_name = TRIM(COALESCE(sp.spec_name, ''))
 AND v.fabric = TRIM(COALESCE(sp.fabric, ''))
SET sp.variant_id = v.id
WHERE sp.variant_id IS NULL;

-- 5) Add FK + index for variant_id
SET @has_variant_idx := (
    SELECT COUNT(1)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND INDEX_NAME = 'idx_sp_variant'
);
SET @sql := IF(@has_variant_idx = 0,
    'ALTER TABLE sales_products ADD INDEX idx_sp_variant (variant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_variant_fk := (
    SELECT COUNT(1)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND CONSTRAINT_NAME = 'fk_sp_variant'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql := IF(@has_variant_fk = 0,
    'ALTER TABLE sales_products ADD CONSTRAINT fk_sp_variant FOREIGN KEY (variant_id) REFERENCES sales_product_variants(id) ON DELETE RESTRICT',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 6) Variant-level order links (replace old sales_product_order_links gradually)
CREATE TABLE IF NOT EXISTS sales_variant_order_links (
    variant_id INT UNSIGNED NOT NULL,
    order_product_id INT UNSIGNED NOT NULL,
    quantity INT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (variant_id, order_product_id),
    CONSTRAINT fk_svol_variant FOREIGN KEY (variant_id)
        REFERENCES sales_product_variants(id) ON DELETE CASCADE,
    CONSTRAINT fk_svol_order FOREIGN KEY (order_product_id)
        REFERENCES order_products(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7) Backfill variant-level links by aggregating existing product-level links
INSERT INTO sales_variant_order_links (variant_id, order_product_id, quantity)
SELECT
    sp.variant_id,
    l.order_product_id,
    SUM(l.quantity) AS qty
FROM sales_product_order_links l
JOIN sales_products sp ON sp.id = l.sales_product_id
WHERE sp.variant_id IS NOT NULL
GROUP BY sp.variant_id, l.order_product_id
ON DUPLICATE KEY UPDATE
    quantity = VALUES(quantity);

-- 8) Platform SKU uniqueness should be per shop (shop_id + platform_sku)
-- Drop old UNIQUE index that only covers platform_sku.
SET @drop_unique_sql := (
    SELECT GROUP_CONCAT(CONCAT('ALTER TABLE sales_products DROP INDEX `', s.INDEX_NAME, '`') SEPARATOR '; ')
    FROM (
        SELECT DISTINCT INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'sales_products'
          AND NON_UNIQUE = 0
          AND INDEX_NAME <> 'PRIMARY'
          AND INDEX_NAME NOT IN ('uk_sales_products_shop_sku')
        GROUP BY INDEX_NAME
        HAVING SUM(CASE WHEN COLUMN_NAME = 'platform_sku' THEN 1 ELSE 0 END) >= 1
           AND COUNT(1) = 1
    ) s
);
SET @sql := IF(@drop_unique_sql IS NULL OR @drop_unique_sql = '', 'SELECT 1', @drop_unique_sql);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_shop_sku_unique := (
    SELECT COUNT(1)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND INDEX_NAME = 'uk_sales_products_shop_sku'
);
SET @sql := IF(@has_shop_sku_unique = 0,
    'ALTER TABLE sales_products ADD UNIQUE KEY uk_sales_products_shop_sku (shop_id, platform_sku)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 9) Parent uniqueness should be per shop (shop_id + parent_code)
-- Drop old global unique on parent_code (if exists), then add composite unique.
SET @drop_parent_unique_sql := (
    SELECT GROUP_CONCAT(CONCAT('ALTER TABLE sales_parents DROP INDEX `', s.INDEX_NAME, '`') SEPARATOR '; ')
    FROM (
        SELECT DISTINCT INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'sales_parents'
          AND NON_UNIQUE = 0
          AND INDEX_NAME <> 'PRIMARY'
          AND INDEX_NAME NOT IN ('uk_sales_parents_shop_parent_code')
        GROUP BY INDEX_NAME
        HAVING SUM(CASE WHEN COLUMN_NAME = 'parent_code' THEN 1 ELSE 0 END) >= 1
           AND COUNT(1) = 1
    ) s
);
SET @sql := IF(@drop_parent_unique_sql IS NULL OR @drop_parent_unique_sql = '', 'SELECT 1', @drop_parent_unique_sql);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_parent_shop_unique := (
    SELECT COUNT(1)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_parents'
      AND INDEX_NAME = 'uk_sales_parents_shop_parent_code'
);
SET @sql := IF(@has_parent_shop_unique = 0,
    'ALTER TABLE sales_parents ADD UNIQUE KEY uk_sales_parents_shop_parent_code (shop_id, parent_code)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 10) Main image mapping can bind to variant level
SET @has_map_variant_col := (
    SELECT COUNT(1)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sku_image_mappings'
      AND COLUMN_NAME = 'variant_id'
);
SET @sql := IF(@has_map_variant_col = 0,
    'ALTER TABLE sku_image_mappings ADD COLUMN variant_id INT UNSIGNED NULL AFTER sales_product_id',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE sku_image_mappings sim
JOIN sales_products sp ON sp.id = sim.sales_product_id
SET sim.variant_id = sp.variant_id
WHERE sim.variant_id IS NULL;

SET @has_map_variant_idx := (
    SELECT COUNT(1)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sku_image_mappings'
      AND INDEX_NAME = 'idx_sim_variant'
);
SET @sql := IF(@has_map_variant_idx = 0,
    'ALTER TABLE sku_image_mappings ADD INDEX idx_sim_variant (variant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_map_variant_fk := (
    SELECT COUNT(1)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sku_image_mappings'
      AND CONSTRAINT_NAME = 'fk_sim_variant'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql := IF(@has_map_variant_fk = 0,
    'ALTER TABLE sku_image_mappings ADD CONSTRAINT fk_sim_variant FOREIGN KEY (variant_id) REFERENCES sales_product_variants(id) ON DELETE CASCADE',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 11) Seed default sales image types (create-only, no edit)
INSERT INTO image_types (name, is_enabled)
SELECT '场景纯图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='场景纯图');

INSERT INTO image_types (name, is_enabled)
SELECT '尺寸图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='尺寸图');

INSERT INTO image_types (name, is_enabled)
SELECT '文字卖点图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='文字卖点图');

INSERT INTO image_types (name, is_enabled)
SELECT '细节纯图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='细节纯图');

INSERT INTO image_types (name, is_enabled)
SELECT '白底纯图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='白底纯图');

INSERT INTO image_types (name, is_enabled)
SELECT '人物纯图', 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM image_types WHERE name='人物纯图');

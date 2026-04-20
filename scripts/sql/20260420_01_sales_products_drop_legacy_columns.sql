-- sales_products 字段清理（兼容执行）
-- 生成时间: 2026-04-20
-- MySQL 错误 #1553 修复：先删除外键再删除 sku_family_id 列
-- 目标:
-- 1) 删除 sales_title（已迁移到父体文案维度）
-- 2) 删除 sales_products.sku_family_id：改由 sales_product_variants 承担
-- 3) 不删除 shop_id：无父体 SKU 无法推导店铺

SET NAMES utf8mb4;

-- =========================
-- 0) 审计统计（执行前风险评估）
-- =========================
SELECT COUNT(*) AS total_products FROM sales_products;
SELECT COUNT(*) AS no_parent_products FROM sales_products WHERE parent_id IS NULL;
SELECT COUNT(*) AS no_variant_products FROM sales_products WHERE variant_id IS NULL;

-- =========================
-- 1) 删除 sales_title（若存在）
-- =========================
SET @has_sales_title := (
    SELECT COUNT(1)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND COLUMN_NAME = 'sales_title'
);
SET @sql := IF(@has_sales_title > 0,
    'ALTER TABLE sales_products DROP COLUMN sales_title',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================
-- 2) 删除 sku_family_id（若存在）
-- =========================
-- 错误分析:
--   MySQL Error #1553: 无法删除索引 'idx_sp_sku_family'：外键约束中需要它
--
-- 解决方案:
--   先删除 sales_products 上的外键，再删除索引和列
--   代码已改为只从 sales_product_variants 读取货号归属
--
SET @has_sp_sku_fk := (
    SELECT COUNT(1)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND CONSTRAINT_NAME = 'fk_sp_sku_family'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql := IF(@has_sp_sku_fk > 0,
    'ALTER TABLE sales_products DROP FOREIGN KEY fk_sp_sku_family',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_sp_sku_index := (
    SELECT COUNT(1)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND INDEX_NAME = 'idx_sp_sku_family'
);
SET @sql := IF(@has_sp_sku_index > 0,
    'ALTER TABLE sales_products DROP INDEX idx_sp_sku_family',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_sp_sku_col := (
    SELECT COUNT(1)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'sales_products'
      AND COLUMN_NAME = 'sku_family_id'
);
SET @sql := IF(@has_sp_sku_col > 0,
    'ALTER TABLE sales_products DROP COLUMN sku_family_id',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================
-- 3) 保留 shop_id（明确决策）
-- =========================
-- 说明: 部分 SKU 无 parent_id，shop_id 不可通过父体推导
SELECT 'KEEP: shop_id column (orphaned products)' AS decision;

-- 脚本完成
SELECT 'Migration: removed sales_title and sku_family_id, preserved shop_id' AS done;
-- 修复 sales_product_performances 表的去重和唯一约束
-- 目标：
-- 1) 根据 (sales_product_id, record_date) 删除重复项，同时保留最新行 (max(id))。
-- 2) 确保 id 为主键为 AUTO_INCREMENT。
-- 3) 在 (sales_product_id, record_date) 上添加唯一键，以便 ON DUPLICATE KEY UPDATE 语句生效。

--- 注意事项：
-- - 此脚本使用动态 SQL 以确保在不同环境下的幂等性。
-- - 请在非高峰时段运行；重复项清理操作可能会锁定表。

START TRANSACTION;

-- 1) De-duplicate: keep the row with max(id) per (sales_product_id, record_date)
DELETE spp
FROM sales_product_performances spp
JOIN (
  SELECT sales_product_id, record_date, MAX(id) AS keep_id, COUNT(*) AS cnt
  FROM sales_product_performances
  GROUP BY sales_product_id, record_date
  HAVING cnt > 1
) d
  ON d.sales_product_id = spp.sales_product_id
 AND d.record_date = spp.record_date
WHERE spp.id <> d.keep_id;

COMMIT;

-- 2) Ensure id is AUTO_INCREMENT (only if not already)
SET @need_ai := (
  SELECT CASE
    WHEN LOWER(EXTRA) LIKE '%auto_increment%' THEN 0
    ELSE 1
  END
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sales_product_performances'
    AND COLUMN_NAME = 'id'
  LIMIT 1
);
SET @sql_ai := IF(@need_ai = 1,
  'ALTER TABLE sales_product_performances MODIFY id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT',
  'SELECT 1'
);
PREPARE stmt_ai FROM @sql_ai;
EXECUTE stmt_ai;
DEALLOCATE PREPARE stmt_ai;

-- 3) Ensure PRIMARY KEY(id)
SET @has_pk := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sales_product_performances'
    AND CONSTRAINT_TYPE = 'PRIMARY KEY'
);
SET @sql_pk := IF(@has_pk = 0,
  'ALTER TABLE sales_product_performances ADD PRIMARY KEY (id)',
  'SELECT 1'
);
PREPARE stmt_pk FROM @sql_pk;
EXECUTE stmt_pk;
DEALLOCATE PREPARE stmt_pk;

-- 4) Ensure UNIQUE(sales_product_id, record_date)
SET @has_uniq := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sales_product_performances'
    AND INDEX_NAME = 'uniq_sales_product_date'
);
SET @sql_uniq := IF(@has_uniq = 0,
  'ALTER TABLE sales_product_performances ADD UNIQUE KEY uniq_sales_product_date (sales_product_id, record_date)',
  'SELECT 1'
);
PREPARE stmt_uniq FROM @sql_uniq;
EXECUTE stmt_uniq;
DEALLOCATE PREPARE stmt_uniq;

-- Optional: speed up range queries (only if not exists)
SET @has_idx_date := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sales_product_performances'
    AND INDEX_NAME = 'idx_record_date'
);
SET @sql_idx_date := IF(@has_idx_date = 0,
  'ALTER TABLE sales_product_performances ADD INDEX idx_record_date (record_date)',
  'SELECT 1'
);
PREPARE stmt_idx_date FROM @sql_idx_date;
EXECUTE stmt_idx_date;
DEALLOCATE PREPARE stmt_idx_date;


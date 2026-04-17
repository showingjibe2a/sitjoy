-- Sales product refactor (phase 2 cleanup, run AFTER application code is switched)
-- Generated: 2026-04-17
-- This script removes deprecated product-level duplicated fields.

SET NAMES utf8mb4;

-- Safety checks: ensure critical variant data exists first.
SELECT COUNT(1) AS variant_rows FROM sales_product_variants;
SELECT COUNT(1) AS product_rows FROM sales_products;

-- 1) Drop deprecated links table only when variant links are ready
-- (Uncomment after verification)
DROP TABLE IF EXISTS sales_product_order_links;

-- 2) Drop deprecated columns on sales_products
-- NOTE: execute only after all API/template logic no longer references these fields.
ALTER TABLE sales_products
    DROP COLUMN dachene_yuncang_no,
    DROP COLUMN fabric,
    DROP COLUMN spec_name,
    DROP COLUMN sale_price_usd,
    DROP COLUMN warehouse_cost_usd,
    DROP COLUMN last_mile_cost_usd,
    DROP COLUMN package_length_in,
    DROP COLUMN package_width_in,
    DROP COLUMN package_height_in,
    DROP COLUMN net_weight_lbs,
    DROP COLUMN gross_weight_lbs;

-- 3) Optional: enforce NOT NULL variant_id when all rows are migrated
ALTER TABLE sales_products
    MODIFY COLUMN variant_id INT UNSIGNED NOT NULL;

-- 4) Optional: enforce NOT NULL shop_id if your business requires every SKU to belong to a shop
ALTER TABLE sales_products
    MODIFY COLUMN shop_id INT UNSIGNED NOT NULL;

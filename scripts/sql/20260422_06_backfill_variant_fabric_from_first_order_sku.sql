-- Backfill sales_product_variants.fabric_id using the first linked order_product (by order_product_id)
-- Generated: 2026-04-22
SET NAMES utf8mb4;

-- Only run after 20260422_05 added fabric_id
UPDATE sales_product_variants v
JOIN (
  SELECT l.variant_id, MIN(l.order_product_id) AS first_order_product_id
  FROM sales_variant_order_links l
  GROUP BY l.variant_id
) x ON x.variant_id = v.id
JOIN order_products op ON op.id = x.first_order_product_id
SET v.fabric_id = op.fabric_id
WHERE (v.fabric_id IS NULL OR v.fabric_id = 0)
  AND op.fabric_id IS NOT NULL AND op.fabric_id > 0;


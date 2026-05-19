-- Move sale_price_usd from sales_product_variants to sales_products (per platform SKU).

ALTER TABLE `sales_products`
  ADD COLUMN `sale_price_usd` decimal(10,2) DEFAULT NULL AFTER `child_code`;

UPDATE `sales_products` sp
INNER JOIN `sales_product_variants` v ON v.id = sp.variant_id
SET sp.sale_price_usd = v.sale_price_usd
WHERE v.sale_price_usd IS NOT NULL;

ALTER TABLE `sales_product_variants`
  DROP COLUMN `sale_price_usd`;

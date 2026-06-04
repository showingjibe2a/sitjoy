-- GTIN / UPC barcodes on sales_products (per platform SKU, not per variant).

ALTER TABLE `sales_products`
  ADD COLUMN `gtin` varchar(32) DEFAULT NULL AFTER `child_code`,
  ADD COLUMN `upc` varchar(32) DEFAULT NULL AFTER `gtin`;

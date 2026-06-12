-- 销售产品：备注

ALTER TABLE `sales_products`
  ADD COLUMN `notes` varchar(512) DEFAULT NULL COMMENT '备注' AFTER `discounted_price_usd`;

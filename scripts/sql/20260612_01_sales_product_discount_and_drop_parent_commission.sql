-- 销售产品：记录实际折扣率；父体：移除不再使用的佣金费率字段

ALTER TABLE `sales_products`
  ADD COLUMN `actual_discount_rate` decimal(8,4) DEFAULT NULL COMMENT '实际设置的折扣率（为空时使用父体预估折扣率）' AFTER `sale_price_usd`;

ALTER TABLE `sales_parents`
  DROP COLUMN `commission_rate`;

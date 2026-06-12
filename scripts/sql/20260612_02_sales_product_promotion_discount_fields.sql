-- 销售产品：活动形式、折扣形式、折扣金额、折后价

ALTER TABLE `sales_products`
  ADD COLUMN `promotion_activity_type` varchar(32) DEFAULT NULL COMMENT '活动形式' AFTER `sale_price_usd`,
  ADD COLUMN `discount_form_type` varchar(16) DEFAULT NULL COMMENT '折扣形式: percent/amount' AFTER `promotion_activity_type`,
  ADD COLUMN `actual_discount_amount_usd` decimal(10,2) DEFAULT NULL COMMENT '折扣金额USD(通常为负数)' AFTER `actual_discount_rate`,
  ADD COLUMN `discounted_price_usd` decimal(10,2) DEFAULT NULL COMMENT '折后价USD' AFTER `actual_discount_amount_usd`;

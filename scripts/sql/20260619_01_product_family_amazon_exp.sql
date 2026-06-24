-- 货号级 Amazon 预估笔单价 / ACOAS（广告调整盈利概率计算）
ALTER TABLE `product_families`
  ADD COLUMN `amazon_exp_atv` DECIMAL(18,4) NULL COMMENT 'Amazon预估笔单价(USD)' AFTER `is_on_market`,
  ADD COLUMN `amazon_exp_acoas` DECIMAL(10,6) NULL COMMENT 'Amazon预估ACOAS比例(0-1)' AFTER `amazon_exp_atv`;

-- 货号级 Amazon 预估 ACOS（盈利概率理论 CPS = 笔单价 × ACOS）
ALTER TABLE `product_families`
  ADD COLUMN `amazon_exp_acos` DECIMAL(10,6) NULL COMMENT 'Amazon预估ACOS比例(0-1)，广告花费/广告销售额' AFTER `amazon_exp_atv`;

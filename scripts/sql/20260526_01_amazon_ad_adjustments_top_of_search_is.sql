-- 广告调整记录：首页首位 IS（百分数，如 12.50%）
ALTER TABLE `amazon_ad_adjustments`
  ADD COLUMN `top_of_search_is` varchar(32) DEFAULT NULL COMMENT '首页首位IS(%)' AFTER `cvr`;

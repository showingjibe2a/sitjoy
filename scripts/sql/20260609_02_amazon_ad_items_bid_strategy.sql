-- 广告活动层级：竞价策略
ALTER TABLE `amazon_ad_items`
  ADD COLUMN `bid_strategy` varchar(32) DEFAULT NULL COMMENT '竞价策略，仅广告活动' AFTER `budget`;

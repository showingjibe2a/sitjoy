-- 广告投放表：amazon_ad_deliveries -> amazon_ad_targets，delivery_desc -> target_desc
ALTER TABLE `amazon_ad_deliveries` DROP FOREIGN KEY `fk_ad_delivery_item`;

RENAME TABLE `amazon_ad_deliveries` TO `amazon_ad_targets`;

ALTER TABLE `amazon_ad_targets`
  CHANGE COLUMN `delivery_desc` `target_desc` varchar(255) NOT NULL COMMENT '投放描述';

ALTER TABLE `amazon_ad_targets`
  RENAME INDEX `idx_ad_delivery_item` TO `idx_ad_target_item`,
  RENAME INDEX `idx_ad_delivery_status` TO `idx_ad_target_status`,
  RENAME INDEX `idx_ad_delivery_next_observe` TO `idx_ad_target_next_observe`;

ALTER TABLE `amazon_ad_targets`
  ADD CONSTRAINT `fk_ad_target_item` FOREIGN KEY (`ad_item_id`) REFERENCES `amazon_ad_items` (`id`) ON DELETE CASCADE;

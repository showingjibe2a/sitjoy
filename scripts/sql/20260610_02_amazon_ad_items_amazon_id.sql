-- amazon_ad_items: optional Amazon entity ID (portfolio / campaign / ad group)
ALTER TABLE `amazon_ad_items`
  ADD COLUMN `amazon_id` varchar(64) DEFAULT NULL COMMENT '亚马逊侧 ID' AFTER `name`;

-- 广告组合关联店铺；活动/广告组继承组合的 shop_id / sku_family_id 由应用层写入

ALTER TABLE `amazon_ad_items`
  ADD COLUMN `shop_id` int(10) UNSIGNED DEFAULT 1 AFTER `sku_family_id`,
  ADD KEY `idx_ad_shop` (`shop_id`),
  ADD CONSTRAINT `fk_ad_shop` FOREIGN KEY (`shop_id`) REFERENCES `shops` (`id`) ON DELETE SET NULL;

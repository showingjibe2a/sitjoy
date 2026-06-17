-- 通道图关联：一张 listing 图（member）可关联一张通道母图（channel）；同一通道图可被多张 member 引用。
CREATE TABLE IF NOT EXISTS `image_asset_channel_links` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `member_asset_id` bigint(20) UNSIGNED NOT NULL COMMENT '被关联的 listing 图片 asset',
  `channel_asset_id` bigint(20) UNSIGNED NOT NULL COMMENT '通道母图 asset',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_member_asset` (`member_asset_id`),
  KEY `idx_channel_asset` (`channel_asset_id`),
  CONSTRAINT `fk_channel_link_member` FOREIGN KEY (`member_asset_id`) REFERENCES `image_assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_channel_link_channel` FOREIGN KEY (`channel_asset_id`) REFERENCES `image_assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `image_types` (`name`, `sort_order`, `is_enabled`, `applies_fabric`, `applies_sales`, `applies_order_product`, `applies_aplus`)
SELECT '通道图', 95, 1, 0, 1, 0, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM `image_types` WHERE `name` = '通道图' LIMIT 1);

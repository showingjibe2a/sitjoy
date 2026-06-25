-- 钉钉通知绑定：由「按页面」改为「按通知功能」
RENAME TABLE `dingtalk_page_notify_bindings` TO `dingtalk_notify_bindings`;

ALTER TABLE `dingtalk_notify_bindings`
  CHANGE COLUMN `page_key` `notify_key` varchar(128) NOT NULL COMMENT '通知功能键，与代码 DINGTALK_NOTIFY_FEATURES.notify_key 一致';

ALTER TABLE `dingtalk_notify_bindings`
  DROP INDEX `uniq_dingtalk_page_key`,
  ADD UNIQUE KEY `uniq_dingtalk_notify_key` (`notify_key`);

-- 将旧页面绑定拆分为对应通知功能（同一群聊、同一启用状态）
INSERT INTO `dingtalk_notify_bindings` (`notify_key`, `dingtalk_group_id`, `is_enabled`)
SELECT 'overseas_restock', `dingtalk_group_id`, `is_enabled`
FROM `dingtalk_notify_bindings`
WHERE `notify_key` = 'logistics_warehouse_inventory_management'
ON DUPLICATE KEY UPDATE
  `dingtalk_group_id` = VALUES(`dingtalk_group_id`),
  `is_enabled` = VALUES(`is_enabled`);

UPDATE `dingtalk_notify_bindings`
SET `notify_key` = 'overseas_stockout'
WHERE `notify_key` = 'logistics_warehouse_inventory_management';

INSERT INTO `dingtalk_notify_bindings` (`notify_key`, `dingtalk_group_id`, `is_enabled`)
SELECT 'transit_listed_available', `dingtalk_group_id`, `is_enabled`
FROM `dingtalk_notify_bindings`
WHERE `notify_key` = 'logistics_in_transit_management'
ON DUPLICATE KEY UPDATE
  `dingtalk_group_id` = VALUES(`dingtalk_group_id`),
  `is_enabled` = VALUES(`is_enabled`);

UPDATE `dingtalk_notify_bindings`
SET `notify_key` = 'transit_eta_delay'
WHERE `notify_key` = 'logistics_in_transit_management';

-- 海外仓低库存预警：默认继承缺货提醒的群聊绑定

INSERT INTO `dingtalk_notify_bindings` (`notify_key`, `dingtalk_group_id`, `is_enabled`)
SELECT 'overseas_low_stock', `dingtalk_group_id`, `is_enabled`
FROM `dingtalk_notify_bindings`
WHERE `notify_key` = 'overseas_stockout'
ON DUPLICATE KEY UPDATE
  `dingtalk_group_id` = VALUES(`dingtalk_group_id`),
  `is_enabled` = VALUES(`is_enabled`);

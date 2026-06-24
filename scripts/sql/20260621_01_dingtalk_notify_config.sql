-- 钉钉群聊配置 + 页面通知绑定
CREATE TABLE `dingtalk_groups` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `group_name` varchar(128) NOT NULL COMMENT '群聊名称（便于识别）',
  `webhook_url` varchar(512) NOT NULL COMMENT '钉钉机器人 Webhook',
  `secret` varchar(255) NOT NULL DEFAULT '' COMMENT '加签 Secret',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注',
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_dingtalk_groups_enabled_name` (`is_enabled`, `group_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `dingtalk_page_notify_bindings` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `page_key` varchar(128) NOT NULL COMMENT '页面权限键，与路由 page_key 一致',
  `dingtalk_group_id` int(10) UNSIGNED NOT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_dingtalk_page_key` (`page_key`),
  KEY `idx_dingtalk_page_binding_group` (`dingtalk_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

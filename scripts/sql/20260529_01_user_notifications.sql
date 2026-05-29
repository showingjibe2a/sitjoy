-- 站内通知中心

CREATE TABLE IF NOT EXISTS `user_notifications` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL,
  `notification_type` varchar(64) NOT NULL DEFAULT 'system',
  `title` varchar(255) NOT NULL DEFAULT '',
  `body` varchar(2000) DEFAULT NULL,
  `link_url` varchar(512) DEFAULT NULL,
  `link_label` varchar(128) DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `read_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_notifications_user_read` (`user_id`, `is_read`, `created_at`),
  KEY `idx_user_notifications_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

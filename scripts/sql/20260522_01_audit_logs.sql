-- 访问日志与操作日志（仅超级管理员 id=1 可在首页查看）

CREATE TABLE IF NOT EXISTS `access_logs` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL,
  `username` varchar(64) NOT NULL DEFAULT '',
  `user_name` varchar(128) DEFAULT NULL,
  `page_path` varchar(255) NOT NULL DEFAULT '',
  `page_key` varchar(64) DEFAULT NULL,
  `page_label` varchar(128) DEFAULT NULL,
  `client_ip` varchar(64) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_access_logs_created_at` (`created_at`),
  KEY `idx_access_logs_user_id` (`user_id`),
  KEY `idx_access_logs_page_path` (`page_path`(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `operation_logs` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL,
  `username` varchar(64) NOT NULL DEFAULT '',
  `user_name` varchar(128) DEFAULT NULL,
  `api_path` varchar(255) NOT NULL DEFAULT '',
  `http_method` varchar(16) NOT NULL DEFAULT '',
  `module_key` varchar(64) DEFAULT NULL,
  `request_summary` text DEFAULT NULL,
  `client_ip` varchar(64) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_operation_logs_created_at` (`created_at`),
  KEY `idx_operation_logs_user_id` (`user_id`),
  KEY `idx_operation_logs_api_path` (`api_path`(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

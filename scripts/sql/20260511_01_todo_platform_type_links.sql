-- 首页待办：与平台类型（platform_types）多选关联
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `todo_platform_type_links` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `todo_id` int(10) UNSIGNED NOT NULL,
  `platform_type_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tptl_todo_platform` (`todo_id`, `platform_type_id`),
  KEY `idx_tptl_todo` (`todo_id`),
  KEY `idx_tptl_platform` (`platform_type_id`),
  CONSTRAINT `fk_tptl_todo` FOREIGN KEY (`todo_id`) REFERENCES `todos` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_tptl_platform_type` FOREIGN KEY (`platform_type_id`) REFERENCES `platform_types` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

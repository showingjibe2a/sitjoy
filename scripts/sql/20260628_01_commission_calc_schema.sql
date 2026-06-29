-- 销售佣金：平台 × 佣金大类规则（货号 commission_group 见 20260628_04；无 priority，未配置则无法计算）
-- params_json 使用 TEXT（兼容 MariaDB 10.0 / 旧版 MySQL，勿用 JSON 类型与 CAST AS JSON）

CREATE TABLE IF NOT EXISTS `commission_calc_rules` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `platform_type_id` INT UNSIGNED NOT NULL,
  `commission_group` VARCHAR(64) NOT NULL COMMENT '佣金大类，如家具、全品类',
  `calc_method` VARCHAR(16) NOT NULL COMMENT 'flat=固定费率 tiered=分段累进',
  `params_json` TEXT NOT NULL COMMENT 'JSON 字符串，由应用层解析',
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_commission_rule` (`platform_type_id`, `commission_group`),
  KEY `idx_commission_rule_platform` (`platform_type_id`),
  CONSTRAINT `fk_commission_rule_platform` FOREIGN KEY (`platform_type_id`) REFERENCES `platform_types` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 家具分段：min(S,200)×15% + max(S−200,0)×10%（Amazon / Walmart）
INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '家具', 'tiered', '{"tiers":[{"up_to":200,"rate":0.15},{"rate":0.10}]}'
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('amazon', '亚马逊')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '家具', 'tiered', '{"tiers":[{"up_to":200,"rate":0.15},{"rate":0.10}]}'
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('walmart', '沃尔玛', 'wal-mart')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

-- Wayfair 全品类固定 4%
INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '全品类', 'flat', '{"rate":0.04}'
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('wayfair')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

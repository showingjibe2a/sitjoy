-- 销售佣金：平台 × 佣金大类规则 + 货号细分类目映射（无 priority，未配置则无法计算）

CREATE TABLE IF NOT EXISTS `commission_calc_rules` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `platform_type_id` INT UNSIGNED NOT NULL,
  `commission_group` VARCHAR(64) NOT NULL COMMENT '佣金大类，如家具、全品类',
  `calc_method` VARCHAR(16) NOT NULL COMMENT 'flat=固定费率 tiered=分段累进',
  `params_json` JSON NOT NULL,
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_commission_rule` (`platform_type_id`, `commission_group`),
  KEY `idx_commission_rule_platform` (`platform_type_id`),
  CONSTRAINT `fk_commission_rule_platform` FOREIGN KEY (`platform_type_id`) REFERENCES `platform_types` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `commission_product_category_mappings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `platform_type_id` INT UNSIGNED NOT NULL,
  `product_category` VARCHAR(64) NOT NULL COMMENT '与 product_families.category 一致；* 表示该平台全部细分类',
  `commission_group` VARCHAR(64) NOT NULL,
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_commission_cat_map` (`platform_type_id`, `product_category`),
  KEY `idx_commission_map_platform` (`platform_type_id`),
  CONSTRAINT `fk_commission_map_platform` FOREIGN KEY (`platform_type_id`) REFERENCES `platform_types` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 家具分段：min(S,200)×15% + max(S−200,0)×10%（Amazon / Walmart）
INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '家具', 'tiered', CAST('{"tiers":[{"up_to":200,"rate":0.15},{"rate":0.10}]}' AS JSON)
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('amazon', '亚马逊')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '家具', 'tiered', CAST('{"tiers":[{"up_to":200,"rate":0.15},{"rate":0.10}]}' AS JSON)
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('walmart', '沃尔玛', 'wal-mart')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

-- Wayfair 全品类固定 4%
INSERT INTO `commission_calc_rules` (`platform_type_id`, `commission_group`, `calc_method`, `params_json`)
SELECT pt.`id`, '全品类', 'flat', CAST('{"rate":0.04}' AS JSON)
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) IN ('wayfair')
ON DUPLICATE KEY UPDATE
  `calc_method` = VALUES(`calc_method`),
  `params_json` = VALUES(`params_json`);

-- Wayfair：细分类目统一映射到全品类（product_category=* 表示任意细分类）
INSERT INTO `commission_product_category_mappings` (`platform_type_id`, `product_category`, `commission_group`)
SELECT pt.`id`, '*', '全品类'
FROM `platform_types` pt
WHERE LOWER(TRIM(pt.`name`)) = 'wayfair'
ON DUPLICATE KEY UPDATE `commission_group` = VALUES(`commission_group`);

-- Amazon / Walmart 细分类目→家具 需按实际货号类目维护，示例：
-- INSERT INTO commission_product_category_mappings (platform_type_id, product_category, commission_group)
-- SELECT id, '单椅', '家具' FROM platform_types WHERE LOWER(TRIM(name)) IN ('amazon','亚马逊');

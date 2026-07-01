-- A+ 重构：版本布局、素材组内排序、图片类型平台字段合并

-- image_types：手机/电脑适用 + 平台 ID 逗号串
ALTER TABLE `image_types`
  ADD COLUMN `applies_mobile` tinyint(1) NOT NULL DEFAULT 1 AFTER `applies_aplus`,
  ADD COLUMN `applies_desktop` tinyint(1) NOT NULL DEFAULT 1 AFTER `applies_mobile`,
  ADD COLUMN `platform_type_ids` varchar(255) DEFAULT NULL COMMENT '逗号分隔 platform_types.id，空=全平台通用' AFTER `applies_desktop`;

-- 从 image_type_platform_types 回填 platform_type_ids
UPDATE `image_types` `it`
LEFT JOIN (
  SELECT `image_type_id`, GROUP_CONCAT(`platform_type_id` ORDER BY `platform_type_id` SEPARATOR ',') AS `pids`
  FROM `image_type_platform_types`
  GROUP BY `image_type_id`
) `m` ON `m`.`image_type_id` = `it`.`id`
SET `it`.`platform_type_ids` = NULLIF(TRIM(`m`.`pids`), '');

-- aplus_version_assets：设备标记 + 组内排序
ALTER TABLE `aplus_version_assets`
  ADD COLUMN `apply_mobile` tinyint(1) NOT NULL DEFAULT 1 AFTER `sort_order`,
  ADD COLUMN `apply_desktop` tinyint(1) NOT NULL DEFAULT 1 AFTER `apply_mobile`,
  ADD COLUMN `item_sort_order` int(10) UNSIGNED NOT NULL DEFAULT 1 AFTER `apply_desktop`;

-- device -> apply_mobile / apply_desktop
UPDATE `aplus_version_assets`
SET `apply_mobile` = CASE WHEN LOWER(`device`) = 'mobile' THEN 1 WHEN LOWER(`device`) = 'desktop' THEN 0 ELSE 1 END,
    `apply_desktop` = CASE WHEN LOWER(`device`) = 'mobile' THEN 0 WHEN LOWER(`device`) = 'desktop' THEN 1 ELSE 1 END;

-- 删除旧列与索引
ALTER TABLE `aplus_version_assets`
  DROP INDEX `idx_apva_type`,
  DROP INDEX `idx_apva_version_layout_type_sort`,
  DROP INDEX `idx_apva_version_device_sort`;

ALTER TABLE `aplus_version_assets`
  DROP COLUMN `image_type_id`,
  DROP COLUMN `device`;

ALTER TABLE `aplus_version_assets`
  ADD KEY `idx_apva_version_group_sort` (`aplus_version_id`, `sort_order`, `item_sort_order`, `id`);

-- 合并表废弃
DROP TABLE IF EXISTS `image_type_platform_types`;

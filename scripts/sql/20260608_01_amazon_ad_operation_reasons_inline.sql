-- 将操作原因内联到 amazon_ad_operation_types.reason_names（JSON 数组），移除 amazon_ad_operation_reasons

ALTER TABLE `amazon_ad_operation_types`
  ADD COLUMN `reason_names` text DEFAULT NULL AFTER `apply_group`;

UPDATE `amazon_ad_operation_types` ot
INNER JOIN (
  SELECT
    `operation_type_id`,
    CONCAT('[', GROUP_CONCAT(JSON_QUOTE(`reason_name`) ORDER BY `id` SEPARATOR ','), ']') AS `names_json`
  FROM `amazon_ad_operation_reasons`
  GROUP BY `operation_type_id`
) agg ON agg.`operation_type_id` = ot.`id`
SET ot.`reason_names` = agg.`names_json`;

ALTER TABLE `amazon_ad_adjustments`
  ADD COLUMN `reason_name` varchar(255) DEFAULT NULL AFTER `after_value`;

UPDATE `amazon_ad_adjustments` a
INNER JOIN `amazon_ad_operation_reasons` r ON r.`id` = a.`reason_id`
SET a.`reason_name` = r.`reason_name`;

ALTER TABLE `amazon_ad_adjustments`
  DROP FOREIGN KEY `fk_ad_adjustment_reason`;

ALTER TABLE `amazon_ad_adjustments`
  DROP KEY `idx_ad_adjustment_reason`,
  DROP COLUMN `reason_id`;

DROP TABLE `amazon_ad_operation_reasons`;

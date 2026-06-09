-- amazon_ad_operation_types: display order for operation type dropdowns
ALTER TABLE `amazon_ad_operation_types`
  ADD COLUMN `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 0 AFTER `name`;

SET @aa_op_type_rn := 0;
UPDATE `amazon_ad_operation_types`
SET `sort_order` = (@aa_op_type_rn := @aa_op_type_rn + 10)
ORDER BY `id` ASC;

ALTER TABLE `amazon_ad_operation_types`
  ADD KEY `idx_ad_operation_type_sort` (`sort_order`);

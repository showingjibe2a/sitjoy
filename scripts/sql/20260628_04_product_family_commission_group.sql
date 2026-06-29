-- 货号 commission_group + 删除细分类目映射表

ALTER TABLE `product_families`
  ADD COLUMN `commission_group` VARCHAR(64) NOT NULL DEFAULT '家具' COMMENT '佣金大类，对应 commission_calc_rules.commission_group';

DROP TABLE IF EXISTS `commission_product_category_mappings`;

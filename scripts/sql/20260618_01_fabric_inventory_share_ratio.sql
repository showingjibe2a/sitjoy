-- 面料-货号关联表：维护相对最高销量面料的库存展示比例（0~1，最高者为 1）
ALTER TABLE `fabric_product_families`
  ADD COLUMN `inventory_share_ratio` DECIMAL(8,6) NULL DEFAULT NULL
  COMMENT '库存展示比例：相对同货号最高销量面料，1=100%'
  AFTER `sku_family_id`;

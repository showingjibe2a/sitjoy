-- 重命名：sku_image_mappings -> sales_variant_image_mappings
-- 说明：
-- - 语义更清晰：该表实际承载的是 sales variant 与 image asset 的映射
-- - 需在业务低峰执行；重命名后请使用新表名访问

RENAME TABLE sku_image_mappings TO sales_variant_image_mappings;

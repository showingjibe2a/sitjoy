-- 图片类型：新增“适用下单产品”范围开关
-- 说明：
-- - 新增字段 applies_order_product（是否适用于下单产品主图管理）
-- - 默认值为 1（是）

ALTER TABLE image_types
ADD COLUMN applies_order_product TINYINT(1) NOT NULL DEFAULT 1
AFTER applies_sales;

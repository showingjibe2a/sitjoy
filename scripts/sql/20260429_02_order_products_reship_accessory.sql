-- 下单产品：补发用配件标记
-- 说明：
-- - 新增字段 is_reship_accessory（是否为补发用配件）
-- - 默认值为 0（否）

ALTER TABLE order_products
ADD COLUMN is_reship_accessory TINYINT(1) NOT NULL DEFAULT 0
AFTER is_on_market;

-- 平台类型：允许的折扣类型（逗号分隔存储，API 层解析为列表）
ALTER TABLE `platform_types`
  ADD COLUMN `discount_types` varchar(512) DEFAULT NULL COMMENT '允许的折扣类型，逗号分隔' AFTER `name`;

-- 沿用销售产品管理原硬编码活动形式，避免升级后下拉为空
UPDATE `platform_types`
SET `discount_types` = 'Coupon,Promotion,BD,Sale,直降,普通专享,大促专享,多种促销'
WHERE `discount_types` IS NULL OR TRIM(`discount_types`) = '';

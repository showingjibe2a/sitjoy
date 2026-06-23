-- 货号在市状态：1=在市，0=下市（默认在市）
ALTER TABLE `product_families`
  ADD COLUMN `is_on_market` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1=在市 0=下市' AFTER `category`;

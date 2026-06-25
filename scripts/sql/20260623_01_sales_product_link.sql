-- 销售产品：产品网页链接

ALTER TABLE `sales_products`
  ADD COLUMN `product_link` varchar(512) DEFAULT NULL COMMENT '产品网页链接' AFTER `child_code`;

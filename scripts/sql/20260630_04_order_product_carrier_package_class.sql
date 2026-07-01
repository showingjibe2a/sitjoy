-- 下单产品：原 package_size_class 拆为 FedEx / UPS / CG 三列
ALTER TABLE order_products
  CHANGE COLUMN package_size_class fedex_package_size_class varchar(64) DEFAULT NULL,
  ADD COLUMN ups_package_size_class varchar(64) DEFAULT NULL AFTER fedex_package_size_class,
  ADD COLUMN cg_package_size_class varchar(64) DEFAULT NULL AFTER ups_package_size_class;

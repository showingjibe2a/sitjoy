-- 下单产品主图：建立 order_product 与 image_asset 的显式映射关系
-- 说明：
-- - 原有 sku_image_mappings 是 variant ↔ image_asset
-- - 下单产品主图使用独立映射表，避免与 variant 语义混淆

CREATE TABLE order_product_image_mappings (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  order_product_id INT UNSIGNED NOT NULL,
  image_asset_id BIGINT UNSIGNED NOT NULL,
  sort_order INT UNSIGNED NOT NULL DEFAULT 100,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_opim_order_image (order_product_id, image_asset_id),
  KEY idx_opim_order_sort (order_product_id, sort_order),
  KEY idx_opim_asset (image_asset_id),
  CONSTRAINT fk_opim_order_product FOREIGN KEY (order_product_id) REFERENCES order_products(id) ON DELETE CASCADE,
  CONSTRAINT fk_opim_image_asset FOREIGN KEY (image_asset_id) REFERENCES image_assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

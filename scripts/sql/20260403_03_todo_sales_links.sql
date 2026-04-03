-- Todo association with SKU / product and completion timestamp
-- Generated: 2026-04-03
SET NAMES utf8mb4;

ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS completed_at DATETIME NULL AFTER status;

CREATE TABLE IF NOT EXISTS todo_sales_links (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    todo_id INT UNSIGNED NOT NULL,
    sales_product_id INT UNSIGNED NULL,
    sku_family_id INT UNSIGNED NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tsl_todo FOREIGN KEY (todo_id)
        REFERENCES todos(id) ON DELETE CASCADE,
    CONSTRAINT fk_tsl_sales_product FOREIGN KEY (sales_product_id)
        REFERENCES sales_products(id) ON DELETE CASCADE,
    CONSTRAINT fk_tsl_sku_family FOREIGN KEY (sku_family_id)
        REFERENCES product_families(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_tsl_todo_sp (todo_id, sales_product_id),
    UNIQUE KEY uniq_tsl_todo_sf (todo_id, sku_family_id),
    INDEX idx_tsl_todo (todo_id),
    INDEX idx_tsl_sales_product (sales_product_id),
    INDEX idx_tsl_sku_family (sku_family_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

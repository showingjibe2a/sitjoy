-- SKU (order_products) <-> factory mapping (many-to-many).
-- Used by row-level visibility and edit-time validation.
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS order_product_factory_links (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_product_id INT UNSIGNED NOT NULL,
    factory_id INT UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_op_factory (order_product_id, factory_id),
    INDEX idx_op_factory_order_product (order_product_id),
    INDEX idx_op_factory_factory (factory_id),
    CONSTRAINT fk_opfl_order_product FOREIGN KEY (order_product_id)
        REFERENCES order_products(id) ON DELETE CASCADE,
    CONSTRAINT fk_opfl_factory FOREIGN KEY (factory_id)
        REFERENCES logistics_factories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional backfill: map existing SKU-factory pairs from inventory tables.
INSERT IGNORE INTO order_product_factory_links (order_product_id, factory_id)
SELECT DISTINCT order_product_id, factory_id FROM factory_stock_inventory
UNION
SELECT DISTINCT order_product_id, factory_id FROM factory_wip_inventory;

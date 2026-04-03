-- Sales product daily performance schema
-- Generated: 2026-04-03
SET NAMES utf8mb4;

-- ----------------------------
-- Table: sales_product_performances
-- Daily metrics keyed by sales_products.id + record_date.
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_product_performances (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sales_product_id INT UNSIGNED NOT NULL,
    record_date DATE NOT NULL,
    sales_qty INT UNSIGNED NOT NULL DEFAULT 0,
    net_sales_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
    order_qty INT UNSIGNED NOT NULL DEFAULT 0,
    session_total INT UNSIGNED NOT NULL DEFAULT 0,
    ad_impressions INT UNSIGNED NOT NULL DEFAULT 0,
    ad_clicks INT UNSIGNED NOT NULL DEFAULT 0,
    ad_orders INT UNSIGNED NOT NULL DEFAULT 0,
    ad_spend DECIMAL(12,2) NOT NULL DEFAULT 0,
    ad_sales_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
    refund_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
    sub_category_rank INT UNSIGNED NULL,
    created_by INT UNSIGNED NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_sales_product_performance (sales_product_id, record_date),
    INDEX idx_sp_perf_date (record_date),
    INDEX idx_sp_perf_product (sales_product_id),
    CONSTRAINT fk_sp_perf_sales_product FOREIGN KEY (sales_product_id)
        REFERENCES sales_products(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

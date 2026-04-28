-- 销售管理 - 销量预测：按规格(variant)分月预测 + 下单SKU(order_product)分月调整
-- 说明：
-- - 主表：sales_forecast_spec_monthly（按 variant_id × forecast_month 唯一）
-- - 子表：sales_forecast_order_sku_monthly（按 variant_id × order_product_id × forecast_month 唯一）
-- - 三段值：initial_qty（首次写入即固定）、prev_qty（上一次的 latest）、latest_qty（当前最新）
-- - 时间戳：created_at（首次写入）、prev_updated_at（上一次的 latest_updated_at）、latest_updated_at（最新一次更新）

CREATE TABLE IF NOT EXISTS sales_forecast_spec_monthly (
    id BIGINT NOT NULL AUTO_INCREMENT,
    variant_id INT NOT NULL,
    forecast_month DATE NOT NULL,

    initial_qty BIGINT NOT NULL DEFAULT 0,
    prev_qty BIGINT NULL,
    latest_qty BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prev_updated_at TIMESTAMP NULL,
    latest_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_forecast_spec_month (variant_id, forecast_month),
    KEY idx_forecast_spec_month (forecast_month),
    KEY idx_forecast_spec_variant (variant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sales_forecast_order_sku_monthly (
    id BIGINT NOT NULL AUTO_INCREMENT,
    variant_id INT NOT NULL,
    order_product_id INT NOT NULL,
    forecast_month DATE NOT NULL,

    initial_qty BIGINT NOT NULL DEFAULT 0,
    prev_qty BIGINT NULL,
    latest_qty BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prev_updated_at TIMESTAMP NULL,
    latest_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_forecast_order_sku_month (variant_id, order_product_id, forecast_month),
    KEY idx_forecast_order_month (forecast_month),
    KEY idx_forecast_order_sku (order_product_id),
    KEY idx_forecast_order_variant (variant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

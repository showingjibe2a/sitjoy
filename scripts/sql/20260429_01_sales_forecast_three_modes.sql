-- 销量预测三维重构：
-- - 新增：sales_forecast_platform_sku_monthly（按销售平台SKU 即 sales_products.id × 月份）
-- - 重建：sales_forecast_order_sku_monthly（去掉 variant_id；按 order_product_id × 月份）
-- - 保留：sales_forecast_spec_monthly（按 variant_id × 月份）
-- 三段值（initial_qty / prev_qty / latest_qty）+ 时间戳保持一致，方便前端做版本对比与角标。

CREATE TABLE IF NOT EXISTS sales_forecast_platform_sku_monthly (
    id BIGINT NOT NULL AUTO_INCREMENT,
    sales_product_id INT NOT NULL,
    forecast_month DATE NOT NULL,

    initial_qty BIGINT NOT NULL DEFAULT 0,
    prev_qty BIGINT NULL,
    latest_qty BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prev_updated_at TIMESTAMP NULL,
    latest_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_forecast_platform_sku_month (sales_product_id, forecast_month),
    KEY idx_forecast_platform_sku_month (forecast_month),
    KEY idx_forecast_platform_sku (sales_product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 旧的 sales_forecast_order_sku_monthly 主键含 variant_id，本次改为以 order_product_id 单独维度。
-- 历史数据极少（迁移上线后第一版本），重建表为新结构。
DROP TABLE IF EXISTS sales_forecast_order_sku_monthly;
CREATE TABLE sales_forecast_order_sku_monthly (
    id BIGINT NOT NULL AUTO_INCREMENT,
    order_product_id INT NOT NULL,
    forecast_month DATE NOT NULL,

    initial_qty BIGINT NOT NULL DEFAULT 0,
    prev_qty BIGINT NULL,
    latest_qty BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prev_updated_at TIMESTAMP NULL,
    latest_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_forecast_order_sku_month (order_product_id, forecast_month),
    KEY idx_forecast_order_month (forecast_month),
    KEY idx_forecast_order_sku (order_product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

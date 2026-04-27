-- 销售管理 - 产品表现看板：周/月聚合快照表（方案A）
-- 说明：
-- - 基础事实表：sales_product_performances（按日）
-- - 聚合表：sales_perf_agg_week / sales_perf_agg_month（按周/按月）
-- - 用途：看板快速查询 + 未来销量预测（分月/分周序列）

CREATE TABLE IF NOT EXISTS sales_perf_agg_week (
    id BIGINT NOT NULL AUTO_INCREMENT,
    sales_product_id INT NOT NULL,

    week_start DATE NOT NULL,
    week_end DATE NOT NULL,
    `year_week` INT NOT NULL,

    source_rows INT NOT NULL DEFAULT 0,

    sales_qty BIGINT NOT NULL DEFAULT 0,
    net_sales_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    order_qty BIGINT NOT NULL DEFAULT 0,
    session_total BIGINT NOT NULL DEFAULT 0,
    ad_impressions BIGINT NOT NULL DEFAULT 0,
    ad_clicks BIGINT NOT NULL DEFAULT 0,
    ad_orders BIGINT NOT NULL DEFAULT 0,
    ad_spend DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    ad_sales_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    refund_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    sub_category_rank_avg DECIMAL(18,4) NULL,

    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_week_sales_product (sales_product_id, `year_week`),
    KEY idx_week_start (week_start),
    KEY idx_week_sp (sales_product_id, week_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sales_perf_agg_month (
    id BIGINT NOT NULL AUTO_INCREMENT,
    sales_product_id INT NOT NULL,

    month_start DATE NOT NULL,
    month_end DATE NOT NULL,
    `year_month` INT NOT NULL,

    source_rows INT NOT NULL DEFAULT 0,

    sales_qty BIGINT NOT NULL DEFAULT 0,
    net_sales_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    order_qty BIGINT NOT NULL DEFAULT 0,
    session_total BIGINT NOT NULL DEFAULT 0,
    ad_impressions BIGINT NOT NULL DEFAULT 0,
    ad_clicks BIGINT NOT NULL DEFAULT 0,
    ad_orders BIGINT NOT NULL DEFAULT 0,
    ad_spend DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    ad_sales_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    refund_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    sub_category_rank_avg DECIMAL(18,4) NULL,

    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_month_sales_product (sales_product_id, `year_month`),
    KEY idx_month_start (month_start),
    KEY idx_month_sp (sales_product_id, month_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


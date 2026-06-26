-- 动销月分母：相对全局最新 record_date 向前 30 天（含首尾）销量快照
-- 由产品表现上传/刷新时在应用层维护，不在运行时建表

CREATE TABLE IF NOT EXISTS `sales_perf_rolling_30d` (
  `sales_product_id` INT NOT NULL,
  `anchor_date` DATE NOT NULL COMMENT '全局最新 record_date（窗口终点）',
  `window_start` DATE NOT NULL COMMENT '窗口起点（含）',
  `window_end` DATE NOT NULL COMMENT '窗口终点（含，= anchor_date）',
  `sales_qty` BIGINT NOT NULL DEFAULT 0,
  `net_sales_amount` DECIMAL(18,2) NOT NULL DEFAULT 0.00,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`sales_product_id`),
  KEY `idx_sp_r30_window` (`window_start`, `window_end`),
  KEY `idx_sp_r30_anchor` (`anchor_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

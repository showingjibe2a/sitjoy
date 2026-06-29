-- 下单 SKU 近 30 天销量快照（与 sales_perf_rolling_30d 同窗口，由表现刷新任务维护）

CREATE TABLE IF NOT EXISTS `sales_perf_op_rolling_30d` (
  `order_product_id` INT NOT NULL,
  `anchor_date` DATE NOT NULL COMMENT '全局最新 record_date（窗口终点）',
  `window_start` DATE NOT NULL COMMENT '窗口起点（含）',
  `window_end` DATE NOT NULL COMMENT '窗口终点（含，= anchor_date）',
  `sales_qty` BIGINT NOT NULL DEFAULT 0 COMMENT '链接变体窗口销量 × BOM 件数汇总',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`order_product_id`),
  KEY `idx_sp_op_r30_window` (`window_start`, `window_end`),
  KEY `idx_sp_op_r30_anchor` (`anchor_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

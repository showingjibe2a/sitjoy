-- 销售产品：折扣分段历史（按起止日期记录，便于后续按时间段查询）

CREATE TABLE IF NOT EXISTS `sales_product_discount_segments` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `sales_product_id` int(10) UNSIGNED NOT NULL COMMENT 'sales_products.id',
  `start_date` date NOT NULL COMMENT '本段折扣生效开始日（含）',
  `end_date` date DEFAULT NULL COMMENT '本段折扣结束日（含）；NULL 表示当前仍生效',
  `promotion_activity_type` varchar(32) DEFAULT NULL COMMENT '活动形式',
  `discount_form_type` varchar(16) DEFAULT NULL COMMENT '折扣形式: percent/amount',
  `actual_discount_rate` decimal(10,4) DEFAULT NULL COMMENT '折扣比例(%)',
  `actual_discount_amount_usd` decimal(10,2) DEFAULT NULL COMMENT '折扣金额USD',
  `discounted_price_usd` decimal(10,2) DEFAULT NULL COMMENT '折后价USD',
  `sale_price_usd` decimal(10,2) DEFAULT NULL COMMENT '段内售价快照',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `created_by` int(10) UNSIGNED DEFAULT NULL COMMENT '写入人 users.id',
  PRIMARY KEY (`id`),
  KEY `idx_sp_discount_seg_product_dates` (`sales_product_id`, `start_date`, `end_date`),
  KEY `idx_sp_discount_seg_product_open` (`sales_product_id`, `end_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='销售产品折扣分段历史';

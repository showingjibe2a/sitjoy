-- 移除小类排名字段，并清理销售指标全为 0 的表现明细（不含计算字段）

START TRANSACTION;

-- 1) 删除明细：除计算字段外，所有销售相关指标均为 0 的行
DELETE FROM sales_product_performances
WHERE sales_qty = 0
  AND net_sales_amount = 0
  AND order_qty = 0
  AND session_total = 0
  AND ad_impressions = 0
  AND ad_clicks = 0
  AND ad_orders = 0
  AND ad_spend = 0
  AND ad_sales_amount = 0
  AND refund_amount = 0;

-- 2) 清理聚合表中同类全 0 快照（source_rows 可能因历史零行而偏大，一并移除）
DELETE FROM sales_perf_agg_month
WHERE sales_qty = 0
  AND net_sales_amount = 0
  AND order_qty = 0
  AND session_total = 0
  AND ad_impressions = 0
  AND ad_clicks = 0
  AND ad_orders = 0
  AND ad_spend = 0
  AND ad_sales_amount = 0
  AND refund_amount = 0;

DELETE FROM sales_perf_agg_week
WHERE sales_qty = 0
  AND net_sales_amount = 0
  AND order_qty = 0
  AND session_total = 0
  AND ad_impressions = 0
  AND ad_clicks = 0
  AND ad_orders = 0
  AND ad_spend = 0
  AND ad_sales_amount = 0
  AND refund_amount = 0;

COMMIT;

ALTER TABLE sales_product_performances DROP COLUMN sub_category_rank;
ALTER TABLE sales_perf_agg_month DROP COLUMN sub_category_rank_avg;
ALTER TABLE sales_perf_agg_week DROP COLUMN sub_category_rank_avg;

-- 下单 SKU rolling 30d 快照一次性回填（需先执行 20260627_01 且 sales_perf_rolling_30d 已有数据）

DELETE FROM sales_perf_op_rolling_30d;

INSERT INTO sales_perf_op_rolling_30d
    (order_product_id, anchor_date, window_start, window_end, sales_qty)
SELECT l.order_product_id,
       r.anchor_date,
       r.window_start,
       r.window_end,
       SUM(COALESCE(r.sales_qty, 0) * GREATEST(1, COALESCE(l.quantity, 1))) AS sales_qty
FROM sales_variant_order_links l
INNER JOIN sales_products sp ON sp.variant_id = l.variant_id
INNER JOIN sales_perf_rolling_30d r ON r.sales_product_id = sp.id
GROUP BY l.order_product_id, r.anchor_date, r.window_start, r.window_end;

-- 动销月 rolling 30d 快照一次性回填（建表 20260626_01 之后执行；anchor 变化后由上传刷新任务维护）
-- 若 sales_product_performances 为空则无需执行

DELETE FROM sales_perf_rolling_30d;

INSERT INTO sales_perf_rolling_30d
    (sales_product_id, anchor_date, window_start, window_end, sales_qty, net_sales_amount)
SELECT spp.sales_product_id,
       anchor.mx AS anchor_date,
       DATE_SUB(anchor.mx, INTERVAL 29 DAY) AS window_start,
       anchor.mx AS window_end,
       SUM(COALESCE(spp.sales_qty, 0)) AS sales_qty,
       SUM(COALESCE(spp.net_sales_amount, 0)) AS net_sales_amount
FROM sales_product_performances spp
CROSS JOIN (SELECT MAX(record_date) AS mx FROM sales_product_performances) anchor
WHERE anchor.mx IS NOT NULL
  AND spp.record_date >= DATE_SUB(anchor.mx, INTERVAL 29 DAY)
  AND spp.record_date <= anchor.mx
GROUP BY spp.sales_product_id, anchor.mx;

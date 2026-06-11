-- 观察间隔改由广告调整页本地设置维护，不再存储于投放/商品表
ALTER TABLE amazon_ad_targets DROP COLUMN observe_interval;
ALTER TABLE amazon_ad_products DROP COLUMN observe_interval;

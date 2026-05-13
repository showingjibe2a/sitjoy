-- 海外仓仓库：Wayfair 侧标识（可选，用于对接/筛选）
ALTER TABLE logistics_overseas_warehouses
ADD COLUMN wayfair_id VARCHAR(128) NULL DEFAULT NULL COMMENT 'Wayfair 仓库/站点标识' AFTER destination_region_id;

-- 店铺是否负责尾程：利润/成本统计是否计入尾程运费
ALTER TABLE `shops`
  ADD COLUMN `handles_last_mile` tinyint(1) UNSIGNED NOT NULL DEFAULT 0
  COMMENT '是否负责尾程(利润统计计入尾程运费)'
  AFTER `brand_id`;

-- 现有 Amazon 店铺默认开启，保持与原先按平台名特判一致的行为
UPDATE `shops` s
JOIN `platform_types` pt ON pt.id = s.platform_type_id
SET s.handles_last_mile = 1
WHERE LOWER(pt.name) LIKE '%amazon%'
   OR pt.name LIKE '%亚马逊%';

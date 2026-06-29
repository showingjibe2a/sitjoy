-- 若 commission_calc_rules 已存在且 params_json 为 JSON 类型，改为 TEXT（兼容旧 MariaDB）。
-- 全新安装（新版 20260628_01 已用 TEXT）可跳过；重复执行 MODIFY 为 TEXT 无害。

ALTER TABLE `commission_calc_rules`
  MODIFY COLUMN `params_json` TEXT NOT NULL COMMENT 'JSON 字符串，由应用层解析';

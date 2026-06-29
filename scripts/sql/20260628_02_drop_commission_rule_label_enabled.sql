-- 若已执行过含 label / is_enabled 的旧版 20260628_01，运行本脚本删除冗余列。
-- 全新安装（仅执行新版 20260628_01）可跳过本文件。

ALTER TABLE `commission_calc_rules` DROP COLUMN `label`;
ALTER TABLE `commission_calc_rules` DROP COLUMN `is_enabled`;

-- 若已误执行含 layout_json_* 的 20260630_02，用本脚本回滚 aplus_versions 上多余列
ALTER TABLE `aplus_versions`
  DROP COLUMN IF EXISTS `layout_json_mobile`,
  DROP COLUMN IF EXISTS `layout_json_desktop`;

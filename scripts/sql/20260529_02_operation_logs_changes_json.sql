-- 操作审计：同一条 operation_logs 记录附带结构化字段变更（可选，不额外增行）

ALTER TABLE `operation_logs`
  ADD COLUMN `changes_json` text DEFAULT NULL AFTER `request_summary`;

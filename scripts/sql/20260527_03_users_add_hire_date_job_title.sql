-- 员工入职时间、岗位（仅管理员在后台维护）
-- 部署后请执行本脚本；应用不会在运行时自动改表。

ALTER TABLE `users`
  ADD COLUMN `hire_date` DATE NULL DEFAULT NULL COMMENT '入职日期' AFTER `birthday`,
  ADD COLUMN `job_title` VARCHAR(128) NULL DEFAULT NULL COMMENT '岗位' AFTER `hire_date`;

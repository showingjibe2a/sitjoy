-- 员工直属上级（users 自关联）
-- 部署后请执行本脚本；应用不会在运行时自动改表。

ALTER TABLE `users`
  ADD COLUMN `direct_supervisor_id` INT(10) UNSIGNED NULL DEFAULT NULL COMMENT '直属上级用户ID' AFTER `job_title`,
  ADD KEY `idx_users_direct_supervisor_id` (`direct_supervisor_id`);

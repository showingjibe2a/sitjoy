-- 用户头像：相对站点 data 目录的路径（如 user_avatars/12.jpg），可为 NULL
-- 部署后请执行本脚本；应用不会在运行时自动改表。

ALTER TABLE `users`
  ADD COLUMN `avatar_path` VARCHAR(512) NULL DEFAULT NULL COMMENT '头像相对路径（data/user_avatars）' AFTER `birthday`;

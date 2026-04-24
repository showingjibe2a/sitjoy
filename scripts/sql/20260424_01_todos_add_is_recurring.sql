-- 为历史库补全待办「是否重复提醒」字段（与基准表 todos 定义一致）
-- 执行后首页/待办 API 可写入 is_recurring；未执行前由应用侧按列是否存在省略该列。
SET NAMES utf8mb4;

ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS is_recurring TINYINT UNSIGNED NOT NULL DEFAULT 0 AFTER reminder_interval_days;

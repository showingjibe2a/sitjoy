-- 首页 - 待办重构：完成状态按负责人(todo_assignments)维度存储；todos 仅存事件内容
-- 目标：
-- - todos：移除 status/completed_at，改为 due_date 与 reminder_interval_days 互斥（业务逻辑约束）
-- - todo_assignments：移除 assignment_status，新增 is_completed + completed_at
-- - 数据回填：将原 todos.status/completed_at 回填到 assignments；缺失 assignment 的用 created_by 补一条
SET NAMES utf8mb4;

-- 1) todo_assignments 新增按人完成字段
ALTER TABLE todo_assignments
    ADD COLUMN IF NOT EXISTS is_completed TINYINT UNSIGNED NOT NULL DEFAULT 0 AFTER assignee_id,
    ADD COLUMN IF NOT EXISTS completed_at DATETIME NULL AFTER is_completed;

-- 2) 回填：将旧 todos.status/completed_at 同步到 assignments（若原字段存在）
--    说明：此段在旧字段不存在时执行不会影响（UPDATE 会报未知列则需要按部署顺序执行本 migration）
UPDATE todo_assignments ta
JOIN todos t ON t.id = ta.todo_id
SET ta.is_completed = CASE WHEN COALESCE(t.status,'open')='done' THEN 1 ELSE 0 END,
    ta.completed_at = CASE WHEN COALESCE(t.status,'open')='done' THEN t.completed_at ELSE NULL END;

-- 3) 补齐：若某些 todo 没有 assignment，则默认分配给创建人
INSERT INTO todo_assignments (todo_id, assignee_id, is_completed, completed_at)
SELECT t.id, t.created_by, 0, NULL
FROM todos t
LEFT JOIN todo_assignments ta ON ta.todo_id = t.id AND ta.assignee_id = t.created_by
WHERE ta.id IS NULL;

-- 4) todos：due_date 与 reminder_interval_days 互斥（先放开为可空，然后做一次清洗）
ALTER TABLE todos
    MODIFY COLUMN due_date DATE NULL,
    MODIFY COLUMN reminder_interval_days INT UNSIGNED NULL;

-- 若为循环任务：due_date 置空；若为非循环任务：reminder_interval_days 置空
UPDATE todos
SET due_date = NULL
WHERE COALESCE(is_recurring,0)=1;

UPDATE todos
SET reminder_interval_days = NULL
WHERE COALESCE(is_recurring,0)=0;

-- 5) 移除旧字段：todos.status / todos.completed_at / todo_assignments.assignment_status
ALTER TABLE todos
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS completed_at;

ALTER TABLE todo_assignments
    DROP COLUMN IF EXISTS assignment_status;

-- 6) 索引：按人取任务 & 排序
ALTER TABLE todo_assignments
    ADD KEY IF NOT EXISTS idx_ta_assignee_completed (assignee_id, is_completed, todo_id),
    ADD KEY IF NOT EXISTS idx_ta_todo_assignee (todo_id, assignee_id);


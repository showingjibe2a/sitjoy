-- 首页 - 待办类型管理：新增 todo_types，并为 todos 增加 todo_type_id 外键
-- 注意：本仓库禁止运行时改表；请在部署时先执行本 migration
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS todo_types (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_name VARCHAR(64) NOT NULL,
    sort_order INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_todo_type_name (type_name),
    KEY idx_todo_type_sort (sort_order, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 默认类型：用于回填历史 todos
INSERT INTO todo_types (type_name, sort_order)
SELECT '默认', 0
WHERE NOT EXISTS (SELECT 1 FROM todo_types WHERE type_name='默认' LIMIT 1);

-- 为 todos 增加类型外键，并回填为“默认”
ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS todo_type_id INT UNSIGNED NULL AFTER id;

SET @default_type_id := (SELECT id FROM todo_types WHERE type_name='默认' ORDER BY id ASC LIMIT 1);
UPDATE todos
SET todo_type_id = @default_type_id
WHERE todo_type_id IS NULL AND @default_type_id IS NOT NULL;

ALTER TABLE todos
    MODIFY COLUMN todo_type_id INT UNSIGNED NOT NULL;

SET @fk_exists := (
    SELECT COUNT(1)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'todos'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
      AND CONSTRAINT_NAME = 'fk_todos_todo_type'
);
SET @fk_sql := IF(@fk_exists = 0,
    'ALTER TABLE todos ADD CONSTRAINT fk_todos_todo_type FOREIGN KEY (todo_type_id) REFERENCES todo_types(id) ON DELETE RESTRICT',
    'SELECT 1'
);
PREPARE stmt_fk FROM @fk_sql;
EXECUTE stmt_fk;
DEALLOCATE PREPARE stmt_fk;

ALTER TABLE todos
    ADD KEY IF NOT EXISTS idx_todos_type_status_due (todo_type_id, status, due_date, id);


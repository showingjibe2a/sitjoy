-- 为历史库补全待办「创建人」字段（应用按 created_by 列表/删除）
-- 已有数据：回填为 users 表最小 id；部署后请按业务核对/修正 created_by
SET NAMES utf8mb4;

ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS created_by INT UNSIGNED NULL AFTER priority;

SET @fallback_uid := (SELECT MIN(id) FROM users LIMIT 1);
UPDATE todos
SET created_by = @fallback_uid
WHERE created_by IS NULL AND @fallback_uid IS NOT NULL;

-- 若 users 表为空，请先创建账号再执行本段
ALTER TABLE todos
    MODIFY COLUMN created_by INT UNSIGNED NOT NULL;

SET @fk_exists := (
    SELECT COUNT(1)
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'todos'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
      AND CONSTRAINT_NAME = 'fk_todos_created_by'
);
SET @fk_sql := IF(@fk_exists = 0,
    'ALTER TABLE todos ADD CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE stmt_fk FROM @fk_sql;
EXECUTE stmt_fk;
DEALLOCATE PREPARE stmt_fk;

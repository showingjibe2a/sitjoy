-- Ensure todos table contains the start_date column expected by the todo API.
-- Safe to run on databases that already have the column.
SET NAMES utf8mb4;

ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS start_date DATE NULL AFTER detail;

UPDATE todos
SET start_date = COALESCE(start_date, due_date, DATE(created_at))
WHERE start_date IS NULL;

ALTER TABLE todos
    MODIFY COLUMN start_date DATE NOT NULL;
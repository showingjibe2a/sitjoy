-- Add missing reminder_interval_days to todos for older databases
-- Generated: 2026-04-21
SET NAMES utf8mb4;

ALTER TABLE todos
    ADD COLUMN IF NOT EXISTS reminder_interval_days INT UNSIGNED NOT NULL DEFAULT 1 AFTER due_date;

-- Store A+ layout JSON (mobile/desktop) on image_types
-- Generated: 2026-04-23
SET NAMES utf8mb4;

ALTER TABLE image_types
  ADD COLUMN aplus_layout_json_mobile LONGTEXT NULL,
  ADD COLUMN aplus_layout_json_desktop LONGTEXT NULL;


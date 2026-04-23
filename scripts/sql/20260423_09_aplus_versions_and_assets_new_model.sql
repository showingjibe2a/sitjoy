-- Update A+ schema to new model:
-- - aplus_versions: remove layout_template_id (no single template binding)
-- - aplus_version_assets: keep (version_id, image_asset_id, image_type_id, sort_order, device)
--   sort_order can repeat; image_asset_id can repeat
-- Generated: 2026-04-23
SET NAMES utf8mb4;

ALTER TABLE aplus_versions DROP COLUMN layout_template_id;

ALTER TABLE aplus_version_assets
  DROP COLUMN layout_template_id,
  ADD COLUMN device VARCHAR(8) NOT NULL DEFAULT 'desktop';

ALTER TABLE aplus_version_assets DROP INDEX uk_apva_version_asset;

CREATE INDEX idx_apva_version_device_sort ON aplus_version_assets (aplus_version_id, device, sort_order, id);
CREATE INDEX idx_apva_asset2 ON aplus_version_assets (image_asset_id);


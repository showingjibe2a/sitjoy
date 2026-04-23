-- Bind A+ assets to (version + layout + image_type)
-- Generated: 2026-04-23
SET NAMES utf8mb4;

ALTER TABLE aplus_version_assets
  ADD COLUMN layout_template_id BIGINT UNSIGNED NULL,
  ADD COLUMN image_type_id INT UNSIGNED NULL;

CREATE INDEX idx_apva_layout ON aplus_version_assets (layout_template_id);
CREATE INDEX idx_apva_type ON aplus_version_assets (image_type_id);
CREATE INDEX idx_apva_version_layout_type_sort ON aplus_version_assets (aplus_version_id, layout_template_id, image_type_id, sort_order, id);

-- Backfill image_type_id from image_assets
UPDATE aplus_version_assets a
LEFT JOIN image_assets ia ON ia.id=a.image_asset_id
SET a.image_type_id = ia.image_type_id
WHERE a.image_type_id IS NULL;

-- Backfill layout_template_id from version selection (best-effort)
UPDATE aplus_version_assets a
LEFT JOIN aplus_versions v ON v.id=a.aplus_version_id
SET a.layout_template_id = v.layout_template_id
WHERE a.layout_template_id IS NULL;


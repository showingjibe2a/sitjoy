-- A+ 图片类型：手机/电脑是否共用图片；移除「适用手机端A+」「适用电脑端A+」
-- 前置：20260630_02 已添加 applies_mobile / applies_desktop（若尚未执行请先执行 02）

ALTER TABLE `image_types`
  ADD COLUMN `aplus_share_images` tinyint(1) NOT NULL DEFAULT 1 COMMENT '1=手机电脑共用图片' AFTER `applies_aplus`;

UPDATE `image_types`
SET `aplus_share_images` = IF(`applies_mobile` = 1 AND `applies_desktop` = 1, 1, 0);

ALTER TABLE `image_types`
  DROP COLUMN `applies_mobile`,
  DROP COLUMN `applies_desktop`;

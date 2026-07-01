-- 图片类型：手机端需求尺寸（共用图时与电脑端保持一致）

ALTER TABLE `image_types`
  ADD COLUMN `required_width_px_mobile` int(11) DEFAULT NULL AFTER `required_height_px`,
  ADD COLUMN `required_height_px_mobile` int(11) DEFAULT NULL AFTER `required_width_px_mobile`;

UPDATE `image_types`
SET `required_width_px_mobile` = `required_width_px`,
    `required_height_px_mobile` = `required_height_px`;

-- 广告细分类：创建活动/广告组时自动投放配置（JSON 数组：名称+竞价）
ALTER TABLE `amazon_ad_subtypes`
  ADD COLUMN `campaign_default_targets` text DEFAULT NULL AFTER `subtype_code`,
  ADD COLUMN `group_default_targets` text DEFAULT NULL AFTER `campaign_default_targets`;

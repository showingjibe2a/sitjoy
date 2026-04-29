-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- 主机： localhost
-- 生成日期： 2026-04-24 09:38:06
-- 服务器版本： 10.11.11-MariaDB
-- PHP 版本： 8.2.28

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- 数据库： `sitjoy`
--

-- --------------------------------------------------------

--
-- 表的结构 `amazon_account_health`
--

CREATE TABLE `amazon_account_health` (
  `id` int(10) UNSIGNED NOT NULL,
  `shop_id` int(10) UNSIGNED NOT NULL,
  `account_health_rating` int(11) NOT NULL,
  `suspected_ip_infringement` int(11) NOT NULL DEFAULT 0,
  `intellectual_property_complaints` int(11) NOT NULL DEFAULT 0,
  `authenticity_customer_complaints` int(11) NOT NULL DEFAULT 0,
  `condition_customer_complaints` int(11) NOT NULL DEFAULT 0,
  `food_safety_issues` int(11) NOT NULL DEFAULT 0,
  `listing_policy_violations` int(11) NOT NULL DEFAULT 0,
  `restricted_product_policy_violations` int(11) NOT NULL DEFAULT 0,
  `customer_review_policy_violations` int(11) NOT NULL DEFAULT 0,
  `other_policy_violations` int(11) NOT NULL DEFAULT 0,
  `regulatory_compliance_issues` int(11) NOT NULL DEFAULT 0,
  `order_defect_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `negative_feedback_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `a_to_z_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `chargeback_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `late_shipment_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `pre_fulfillment_cancel_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `valid_tracking_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `on_time_delivery_rate` decimal(8,4) NOT NULL DEFAULT 0.0000,
  `record_datetime` datetime NOT NULL DEFAULT current_timestamp(),
  `remark` varchar(500) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_adjustments`
--

CREATE TABLE `amazon_ad_adjustments` (
  `id` int(10) UNSIGNED NOT NULL,
  `adjust_date` datetime NOT NULL,
  `ad_item_id` int(10) UNSIGNED NOT NULL,
  `operation_type_id` int(10) UNSIGNED NOT NULL,
  `target_object` varchar(255) NOT NULL,
  `before_value` varchar(64) DEFAULT NULL,
  `after_value` varchar(64) DEFAULT NULL,
  `reason_id` int(10) UNSIGNED DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `impressions` varchar(32) DEFAULT NULL,
  `clicks` varchar(32) DEFAULT NULL,
  `cost` varchar(32) DEFAULT NULL,
  `orders` varchar(32) DEFAULT NULL,
  `sales` varchar(32) DEFAULT NULL,
  `acos` varchar(32) DEFAULT NULL,
  `cpc` varchar(32) DEFAULT NULL,
  `ctr` varchar(32) DEFAULT NULL,
  `cvr` varchar(32) DEFAULT NULL,
  `attribution_checked` tinyint(1) NOT NULL DEFAULT 0,
  `attribution_orders` varchar(32) DEFAULT NULL,
  `attribution_sales` varchar(32) DEFAULT NULL,
  `remark` varchar(255) DEFAULT NULL,
  `is_quick_submit` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_deliveries`
--

CREATE TABLE `amazon_ad_deliveries` (
  `id` int(10) UNSIGNED NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT '启动',
  `ad_item_id` int(10) UNSIGNED NOT NULL,
  `delivery_desc` varchar(255) NOT NULL,
  `bid_value` varchar(32) DEFAULT NULL,
  `observe_interval` varchar(64) DEFAULT NULL,
  `next_observe_at` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_items`
--

CREATE TABLE `amazon_ad_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `ad_level` varchar(16) NOT NULL,
  `sku_family_id` int(10) UNSIGNED DEFAULT NULL,
  `portfolio_id` int(10) UNSIGNED DEFAULT NULL,
  `campaign_id` int(10) UNSIGNED DEFAULT NULL,
  `strategy_code` varchar(8) DEFAULT NULL,
  `subtype_id` int(10) UNSIGNED DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `is_shared_budget` tinyint(1) DEFAULT NULL,
  `status` varchar(16) DEFAULT NULL,
  `budget` decimal(12,2) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_operation_reasons`
--

CREATE TABLE `amazon_ad_operation_reasons` (
  `id` int(10) UNSIGNED NOT NULL,
  `operation_type_id` int(10) UNSIGNED NOT NULL,
  `reason_name` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_operation_types`
--

CREATE TABLE `amazon_ad_operation_types` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `apply_campaign` tinyint(1) NOT NULL DEFAULT 1,
  `apply_group` tinyint(1) NOT NULL DEFAULT 1,
  `apply_portfolio` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_products`
--

CREATE TABLE `amazon_ad_products` (
  `id` int(10) UNSIGNED NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT '启动',
  `ad_item_id` int(10) UNSIGNED NOT NULL,
  `sales_product_id` int(10) UNSIGNED NOT NULL,
  `observe_interval` varchar(64) DEFAULT NULL,
  `next_observe_at` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_subtypes`
--

CREATE TABLE `amazon_ad_subtypes` (
  `id` int(10) UNSIGNED NOT NULL,
  `description` varchar(255) NOT NULL,
  `ad_class` varchar(8) NOT NULL DEFAULT 'SP',
  `subtype_code` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_ad_subtype_operation_types`
--

CREATE TABLE `amazon_ad_subtype_operation_types` (
  `subtype_id` int(10) UNSIGNED NOT NULL,
  `operation_type_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_keywords`
--

CREATE TABLE `amazon_keywords` (
  `id` int(10) UNSIGNED NOT NULL,
  `category_id` int(10) UNSIGNED NOT NULL,
  `user_search_term` varchar(255) NOT NULL,
  `search_rank` int(11) DEFAULT NULL,
  `rank_updated_at` datetime DEFAULT NULL,
  `previous_search_rank` int(11) DEFAULT NULL,
  `previous_rank_updated_at` datetime DEFAULT NULL,
  `top_click_asin1` varchar(64) DEFAULT NULL,
  `top_click_asin1_click_share` varchar(32) DEFAULT NULL,
  `top_click_asin1_conversion_share` varchar(32) DEFAULT NULL,
  `top_click_asin2` varchar(64) DEFAULT NULL,
  `top_click_asin2_click_share` varchar(32) DEFAULT NULL,
  `top_click_asin2_conversion_share` varchar(32) DEFAULT NULL,
  `top_click_asin3` varchar(64) DEFAULT NULL,
  `top_click_asin3_click_share` varchar(32) DEFAULT NULL,
  `top_click_asin3_conversion_share` varchar(32) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_keyword_sku_rel`
--

CREATE TABLE `amazon_keyword_sku_rel` (
  `keyword_id` int(10) UNSIGNED NOT NULL,
  `sku_family_id` int(10) UNSIGNED NOT NULL,
  `relevance_score` tinyint(3) UNSIGNED NOT NULL DEFAULT 1,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_keyword_tags`
--

CREATE TABLE `amazon_keyword_tags` (
  `id` int(10) UNSIGNED NOT NULL,
  `category_id` int(10) UNSIGNED NOT NULL,
  `tag_name` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `amazon_keyword_tag_rel`
--

CREATE TABLE `amazon_keyword_tag_rel` (
  `keyword_id` int(10) UNSIGNED NOT NULL,
  `tag_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `aplus_versions`
--

CREATE TABLE `aplus_versions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `version_name` varchar(128) NOT NULL,
  `platform_type_id` int(10) UNSIGNED NOT NULL,
  `sku_family_id` int(10) UNSIGNED NOT NULL,
  `created_by` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `aplus_version_assets`
--

CREATE TABLE `aplus_version_assets` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `aplus_version_id` bigint(20) UNSIGNED NOT NULL,
  `image_asset_id` int(10) UNSIGNED NOT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `image_type_id` int(10) UNSIGNED DEFAULT NULL,
  `device` varchar(8) NOT NULL DEFAULT 'desktop'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `brands`
--

CREATE TABLE `brands` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `certifications`
--

CREATE TABLE `certifications` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `icon_name` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `fabric_image_mappings`
--

CREATE TABLE `fabric_image_mappings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `fabric_id` int(10) UNSIGNED NOT NULL,
  `image_asset_id` bigint(20) UNSIGNED NOT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `created_by` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `fabric_materials`
--

CREATE TABLE `fabric_materials` (
  `id` int(10) UNSIGNED NOT NULL,
  `fabric_code` varchar(64) NOT NULL,
  `fabric_name_en` varchar(128) NOT NULL,
  `representative_color` varchar(7) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `material_id` int(10) UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `fabric_product_families`
--

CREATE TABLE `fabric_product_families` (
  `fabric_id` int(10) UNSIGNED NOT NULL,
  `sku_family_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `factory_contracts`
--

CREATE TABLE `factory_contracts` (
  `id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED DEFAULT NULL,
  `contract_no` varchar(128) NOT NULL,
  `order_no` varchar(128) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `factory_stock_inventory`
--

CREATE TABLE `factory_stock_inventory` (
  `id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `quantity` int(11) NOT NULL DEFAULT 0,
  `notes` text DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `factory_wip_inventory`
--

CREATE TABLE `factory_wip_inventory` (
  `id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `contract_id` int(10) UNSIGNED DEFAULT NULL,
  `quantity` int(11) NOT NULL DEFAULT 0,
  `expected_completion_date` date DEFAULT NULL,
  `initial_expected_completion_date` date DEFAULT NULL,
  `is_completed` tinyint(1) NOT NULL DEFAULT 0,
  `actual_completion_date` date DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `update_time` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `features`
--

CREATE TABLE `features` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `name_en` varchar(128) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `feature_categories`
--

CREATE TABLE `feature_categories` (
  `feature_id` int(10) UNSIGNED NOT NULL,
  `category_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `image_assets`
--

CREATE TABLE `image_assets` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `sha256` char(64) NOT NULL,
  `storage_path` varchar(512) NOT NULL COMMENT 'relative file path under resources',
  `image_type_id` int(10) UNSIGNED DEFAULT NULL,
  `is_deprecated` tinyint(1) NOT NULL DEFAULT 0,
  `description` varchar(1000) DEFAULT NULL COMMENT 'image-level description only',
  `created_by` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `image_types`
--

CREATE TABLE `image_types` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(64) NOT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 100,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `applies_fabric` tinyint(1) NOT NULL DEFAULT 1,
  `applies_sales` tinyint(1) NOT NULL DEFAULT 1,
  `applies_aplus` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `required_width_px` int(11) DEFAULT NULL,
  `required_height_px` int(11) DEFAULT NULL,
  `aplus_layout_json_mobile` longtext DEFAULT NULL,
  `aplus_layout_json_desktop` longtext DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `image_type_platform_types`
--

CREATE TABLE `image_type_platform_types` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `image_type_id` int(10) UNSIGNED NOT NULL,
  `platform_type_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_destination_regions`
--

CREATE TABLE `logistics_destination_regions` (
  `id` int(10) UNSIGNED NOT NULL,
  `region_name` varchar(64) NOT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 100,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_factories`
--

CREATE TABLE `logistics_factories` (
  `id` int(10) UNSIGNED NOT NULL,
  `factory_name` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_forwarders`
--

CREATE TABLE `logistics_forwarders` (
  `id` int(10) UNSIGNED NOT NULL,
  `forwarder_name` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_in_transit`
--

CREATE TABLE `logistics_in_transit` (
  `id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `factory_ship_date_initial` date DEFAULT NULL,
  `factory_ship_date_previous` date DEFAULT NULL,
  `factory_ship_date_latest` date DEFAULT NULL,
  `forwarder_id` int(10) UNSIGNED DEFAULT NULL,
  `logistics_box_no` varchar(128) DEFAULT NULL,
  `customs_clearance_no` varchar(128) DEFAULT NULL,
  `etd_initial` date DEFAULT NULL,
  `etd_previous` date DEFAULT NULL,
  `etd_latest` date DEFAULT NULL,
  `eta_initial` date DEFAULT NULL,
  `eta_previous` date DEFAULT NULL,
  `eta_latest` date DEFAULT NULL,
  `arrival_port_date` date DEFAULT NULL,
  `expected_warehouse_date` date DEFAULT NULL,
  `expected_listed_date_initial` date DEFAULT NULL,
  `expected_listed_date_latest` date DEFAULT NULL,
  `listed_date` date DEFAULT NULL,
  `shipping_company` varchar(128) DEFAULT NULL,
  `vessel_voyage` varchar(128) DEFAULT NULL,
  `bill_of_lading_no` varchar(128) DEFAULT NULL,
  `declaration_docs_provided` tinyint(1) NOT NULL DEFAULT 0,
  `inventory_registered` tinyint(1) NOT NULL DEFAULT 0,
  `clearance_docs_provided` tinyint(1) NOT NULL DEFAULT 0,
  `qty_verified` tinyint(1) NOT NULL DEFAULT 0,
  `qty_consistent` tinyint(1) NOT NULL DEFAULT 0,
  `financial_verified` tinyint(1) NOT NULL DEFAULT 0,
  `port_of_loading` varchar(128) DEFAULT NULL,
  `port_of_destination` varchar(128) DEFAULT NULL,
  `destination_region_id` int(10) UNSIGNED DEFAULT NULL,
  `destination_warehouse_id` int(10) UNSIGNED DEFAULT NULL,
  `confirmed_boxed_qty` tinyint(1) NOT NULL DEFAULT 0,
  `inbound_order_no` varchar(128) DEFAULT NULL,
  `remark` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_in_transit_items`
--

CREATE TABLE `logistics_in_transit_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `transit_id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `shipped_qty` int(11) NOT NULL DEFAULT 0,
  `listed_qty` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_overseas_inventory`
--

CREATE TABLE `logistics_overseas_inventory` (
  `id` int(10) UNSIGNED NOT NULL,
  `warehouse_id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `available_qty` int(11) NOT NULL DEFAULT 0,
  `in_transit_qty` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_overseas_warehouses`
--

CREATE TABLE `logistics_overseas_warehouses` (
  `id` int(10) UNSIGNED NOT NULL,
  `warehouse_name` varchar(255) NOT NULL,
  `supplier_id` int(10) UNSIGNED NOT NULL,
  `warehouse_short_name` varchar(128) NOT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `region` varchar(32) NOT NULL,
  `destination_region_id` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `logistics_suppliers`
--

CREATE TABLE `logistics_suppliers` (
  `id` int(10) UNSIGNED NOT NULL,
  `supplier_name` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `materials`
--

CREATE TABLE `materials` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `name_en` varchar(128) NOT NULL DEFAULT '',
  `material_type_id` int(10) UNSIGNED NOT NULL,
  `parent_id` int(10) UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `material_types`
--

CREATE TABLE `material_types` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_products`
--

CREATE TABLE `order_products` (
  `id` int(10) UNSIGNED NOT NULL,
  `sku` varchar(64) NOT NULL,
  `sku_family_id` int(10) UNSIGNED DEFAULT NULL,
  `version_no` varchar(64) NOT NULL,
  `fabric_id` int(10) UNSIGNED DEFAULT NULL,
  `spec_qty_short` varchar(128) NOT NULL,
  `contents_desc_en` varchar(255) DEFAULT NULL,
  `finished_length_in` decimal(10,2) DEFAULT NULL,
  `finished_width_in` decimal(10,2) DEFAULT NULL,
  `finished_height_in` decimal(10,2) DEFAULT NULL,
  `net_weight_lbs` decimal(10,2) DEFAULT NULL,
  `package_length_in` decimal(10,2) DEFAULT NULL,
  `package_width_in` decimal(10,2) DEFAULT NULL,
  `package_height_in` decimal(10,2) DEFAULT NULL,
  `gross_weight_lbs` decimal(10,2) DEFAULT NULL,
  `cost_usd` decimal(10,2) DEFAULT NULL,
  `carton_qty` int(10) UNSIGNED DEFAULT NULL,
  `package_size_class` varchar(64) DEFAULT NULL,
  `last_mile_avg_freight_usd` decimal(10,2) DEFAULT NULL,
  `factory_wip_stock` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `is_iteration` tinyint(1) NOT NULL DEFAULT 0,
  `is_dachene_product` tinyint(1) NOT NULL DEFAULT 0,
  `is_on_market` tinyint(1) NOT NULL DEFAULT 1,
  `source_order_product_id` int(10) UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_certifications`
--

CREATE TABLE `order_product_certifications` (
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `certification_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_factory_links`
--

CREATE TABLE `order_product_factory_links` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_features`
--

CREATE TABLE `order_product_features` (
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `feature_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_materials`
--

CREATE TABLE `order_product_materials` (
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `material_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_shipping_plans`
--

CREATE TABLE `order_product_shipping_plans` (
  `id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `plan_name` varchar(128) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `order_product_shipping_plan_items`
--

CREATE TABLE `order_product_shipping_plan_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `shipping_plan_id` int(10) UNSIGNED NOT NULL,
  `substitute_order_product_id` int(10) UNSIGNED NOT NULL,
  `quantity` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `platform_types`
--

CREATE TABLE `platform_types` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `product_categories`
--

CREATE TABLE `product_categories` (
  `id` int(10) UNSIGNED NOT NULL,
  `category_cn` varchar(64) NOT NULL,
  `category_en` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `category_en_name` varchar(128) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `product_families`
--

CREATE TABLE `product_families` (
  `id` int(10) UNSIGNED NOT NULL,
  `sku_family` varchar(64) NOT NULL,
  `category` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_order_registrations`
--

CREATE TABLE `sales_order_registrations` (
  `id` int(10) UNSIGNED NOT NULL,
  `shop_id` int(10) UNSIGNED DEFAULT NULL,
  `order_no` varchar(128) NOT NULL,
  `order_date` date DEFAULT NULL,
  `customer_name` varchar(128) DEFAULT NULL,
  `phone` varchar(64) DEFAULT NULL,
  `zip_code` varchar(16) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `city` varchar(64) DEFAULT NULL,
  `state` varchar(32) DEFAULT NULL,
  `shipping_status` varchar(32) NOT NULL DEFAULT 'pending',
  `is_review_invited` tinyint(1) NOT NULL DEFAULT 0,
  `is_logistics_emailed` tinyint(1) NOT NULL DEFAULT 0,
  `compensation_action` varchar(255) DEFAULT NULL,
  `remark` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_order_registration_logistics_items`
--

CREATE TABLE `sales_order_registration_logistics_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `registration_id` int(10) UNSIGNED NOT NULL,
  `shipping_carrier` varchar(128) DEFAULT NULL,
  `tracking_no` varchar(255) DEFAULT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_order_registration_platform_items`
--

CREATE TABLE `sales_order_registration_platform_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `registration_id` int(10) UNSIGNED NOT NULL,
  `sales_product_id` int(10) UNSIGNED DEFAULT NULL,
  `platform_sku` varchar(128) NOT NULL,
  `quantity` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `shipping_plan_id` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_order_registration_shipment_items`
--

CREATE TABLE `sales_order_registration_shipment_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `registration_id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED DEFAULT NULL,
  `order_sku` varchar(64) NOT NULL,
  `quantity` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `source_type` varchar(16) NOT NULL DEFAULT 'manual',
  `shipping_plan_id` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_parents`
--

CREATE TABLE `sales_parents` (
  `id` int(10) UNSIGNED NOT NULL,
  `parent_code` varchar(64) NOT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `shop_id` int(10) UNSIGNED DEFAULT NULL,
  `sku_marker` varchar(128) DEFAULT NULL,
  `estimated_refund_rate` decimal(8,4) DEFAULT NULL,
  `estimated_discount_rate` decimal(8,4) DEFAULT NULL,
  `commission_rate` decimal(8,4) DEFAULT NULL,
  `estimated_acoas` decimal(8,4) DEFAULT NULL,
  `sales_title` varchar(200) DEFAULT NULL,
  `sales_intro` varchar(500) DEFAULT NULL,
  `sales_bullet_1` varchar(500) DEFAULT NULL,
  `sales_bullet_2` varchar(500) DEFAULT NULL,
  `sales_bullet_3` varchar(500) DEFAULT NULL,
  `sales_bullet_4` varchar(500) DEFAULT NULL,
  `sales_bullet_5` varchar(500) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_products`
--

CREATE TABLE `sales_products` (
  `id` int(10) UNSIGNED NOT NULL,
  `shop_id` int(10) UNSIGNED NOT NULL,
  `platform_sku` varchar(128) NOT NULL,
  `product_status` varchar(16) NOT NULL DEFAULT 'enabled',
  `variant_id` int(10) UNSIGNED NOT NULL,
  `parent_id` int(10) UNSIGNED DEFAULT NULL,
  `child_code` varchar(64) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_product_performances`
--

CREATE TABLE `sales_product_performances` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `sales_product_id` int(10) UNSIGNED NOT NULL,
  `record_date` date NOT NULL,
  `sales_qty` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `net_sales_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `order_qty` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `session_total` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `ad_impressions` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `ad_clicks` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `ad_orders` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `ad_spend` decimal(12,2) NOT NULL DEFAULT 0.00,
  `ad_sales_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `refund_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `sub_category_rank` int(10) UNSIGNED DEFAULT NULL,
  `created_by` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_product_variants`
--

CREATE TABLE `sales_product_variants` (
  `id` int(10) UNSIGNED NOT NULL,
  `sku_family_id` int(10) UNSIGNED NOT NULL,
  `spec_name` varchar(255) NOT NULL,
  `fabric_id` int(10) UNSIGNED DEFAULT NULL,
  `sale_price_usd` decimal(10,2) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_variant_order_links`
--

CREATE TABLE `sales_variant_order_links` (
  `variant_id` int(10) UNSIGNED NOT NULL,
  `order_product_id` int(10) UNSIGNED NOT NULL,
  `quantity` int(10) UNSIGNED NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sessions`
--

CREATE TABLE `sessions` (
  `session_id` varchar(128) NOT NULL,
  `employee_id` int(10) UNSIGNED NOT NULL,
  `expires_at` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `shops`
--

CREATE TABLE `shops` (
  `id` int(10) UNSIGNED NOT NULL,
  `shop_name` varchar(128) NOT NULL,
  `platform_type_id` int(10) UNSIGNED NOT NULL,
  `brand_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `sales_variant_image_mappings`
--

CREATE TABLE `sales_variant_image_mappings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `variant_id` int(10) UNSIGNED DEFAULT NULL,
  `image_asset_id` bigint(20) UNSIGNED NOT NULL,
  `sort_order` int(10) UNSIGNED NOT NULL DEFAULT 100,
  `created_by` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `todos`
--

CREATE TABLE `todos` (
  `id` int(10) UNSIGNED NOT NULL,
  `title` varchar(255) NOT NULL,
  `detail` text DEFAULT NULL,
  `start_date` date NOT NULL,
  `due_date` date NOT NULL,
  `reminder_interval_days` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `is_recurring` tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
  `status` varchar(16) NOT NULL DEFAULT 'open',
  `completed_at` datetime DEFAULT NULL,
  `priority` tinyint(3) UNSIGNED NOT NULL DEFAULT 2,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `todo_assignments`
--

CREATE TABLE `todo_assignments` (
  `id` int(10) UNSIGNED NOT NULL,
  `todo_id` int(10) UNSIGNED NOT NULL,
  `assignee_id` int(10) UNSIGNED NOT NULL,
  `assignment_status` varchar(16) NOT NULL DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `todo_sales_links`
--

CREATE TABLE `todo_sales_links` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `todo_id` int(10) UNSIGNED NOT NULL,
  `sales_product_id` int(10) UNSIGNED DEFAULT NULL,
  `sku_family_id` int(10) UNSIGNED DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `users`
--

CREATE TABLE `users` (
  `id` int(10) UNSIGNED NOT NULL,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `name` varchar(128) DEFAULT NULL,
  `phone` varchar(64) DEFAULT NULL,
  `birthday` date DEFAULT NULL,
  `is_admin` tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
  `can_grant_admin` tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
  `page_permissions` longtext DEFAULT NULL,
  `is_approved` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- 表的结构 `user_factory_scopes`
--

CREATE TABLE `user_factory_scopes` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- 转储表的索引
--

--
-- 表的索引 `amazon_account_health`
--
ALTER TABLE `amazon_account_health`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_aah_shop_date` (`shop_id`,`record_datetime`),
  ADD KEY `idx_aah_record_datetime` (`record_datetime`);

--
-- 表的索引 `amazon_ad_adjustments`
--
ALTER TABLE `amazon_ad_adjustments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_ad_adjustment_ad_item` (`ad_item_id`),
  ADD KEY `idx_ad_adjustment_operation` (`operation_type_id`),
  ADD KEY `idx_ad_adjustment_reason` (`reason_id`),
  ADD KEY `idx_ad_adjustment_date` (`adjust_date`);

--
-- 表的索引 `amazon_ad_deliveries`
--
ALTER TABLE `amazon_ad_deliveries`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_ad_delivery_item` (`ad_item_id`),
  ADD KEY `idx_ad_delivery_status` (`status`),
  ADD KEY `idx_ad_delivery_next_observe` (`next_observe_at`);

--
-- 表的索引 `amazon_ad_items`
--
ALTER TABLE `amazon_ad_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_ad_level` (`ad_level`),
  ADD KEY `idx_ad_sku` (`sku_family_id`),
  ADD KEY `idx_ad_portfolio` (`portfolio_id`),
  ADD KEY `idx_ad_campaign` (`campaign_id`),
  ADD KEY `idx_ad_subtype` (`subtype_id`);

--
-- 表的索引 `amazon_ad_operation_reasons`
--
ALTER TABLE `amazon_ad_operation_reasons`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_ad_op_reason` (`operation_type_id`,`reason_name`),
  ADD KEY `idx_ad_op_reason_type` (`operation_type_id`);

--
-- 表的索引 `amazon_ad_operation_types`
--
ALTER TABLE `amazon_ad_operation_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `amazon_ad_products`
--
ALTER TABLE `amazon_ad_products`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_ad_product_item` (`ad_item_id`),
  ADD KEY `idx_ad_product_sales` (`sales_product_id`),
  ADD KEY `idx_ad_product_status` (`status`),
  ADD KEY `idx_ad_product_next_observe` (`next_observe_at`);

--
-- 表的索引 `amazon_ad_subtypes`
--
ALTER TABLE `amazon_ad_subtypes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_ad_subtype` (`ad_class`,`subtype_code`);

--
-- 表的索引 `amazon_ad_subtype_operation_types`
--
ALTER TABLE `amazon_ad_subtype_operation_types`
  ADD PRIMARY KEY (`subtype_id`,`operation_type_id`),
  ADD KEY `fk_ad_subtype_op_type` (`operation_type_id`);

--
-- 表的索引 `amazon_keywords`
--
ALTER TABLE `amazon_keywords`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_amazon_keyword_term` (`user_search_term`),
  ADD KEY `idx_amazon_keyword_category` (`category_id`),
  ADD KEY `idx_amazon_keyword_rank_updated` (`rank_updated_at`);

--
-- 表的索引 `amazon_keyword_sku_rel`
--
ALTER TABLE `amazon_keyword_sku_rel`
  ADD PRIMARY KEY (`keyword_id`,`sku_family_id`),
  ADD KEY `idx_keyword_sku_rel_sku` (`sku_family_id`);

--
-- 表的索引 `amazon_keyword_tags`
--
ALTER TABLE `amazon_keyword_tags`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_keyword_tag` (`category_id`,`tag_name`),
  ADD KEY `idx_keyword_tag_category` (`category_id`);

--
-- 表的索引 `amazon_keyword_tag_rel`
--
ALTER TABLE `amazon_keyword_tag_rel`
  ADD PRIMARY KEY (`keyword_id`,`tag_id`),
  ADD KEY `fk_keyword_tag_rel_tag` (`tag_id`);

--
-- 表的索引 `aplus_versions`
--
ALTER TABLE `aplus_versions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_aplus_version` (`platform_type_id`,`sku_family_id`,`version_name`),
  ADD KEY `idx_aplus_platform` (`platform_type_id`),
  ADD KEY `idx_aplus_sku_family` (`sku_family_id`);

--
-- 表的索引 `aplus_version_assets`
--
ALTER TABLE `aplus_version_assets`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_apva_version_sort` (`aplus_version_id`,`sort_order`,`id`),
  ADD KEY `idx_apva_asset` (`image_asset_id`),
  ADD KEY `idx_apva_type` (`image_type_id`),
  ADD KEY `idx_apva_version_layout_type_sort` (`aplus_version_id`,`image_type_id`,`sort_order`,`id`),
  ADD KEY `idx_apva_version_device_sort` (`aplus_version_id`,`device`,`sort_order`,`id`),
  ADD KEY `idx_apva_asset2` (`image_asset_id`);

--
-- 表的索引 `brands`
--
ALTER TABLE `brands`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `certifications`
--
ALTER TABLE `certifications`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `fabric_image_mappings`
--
ALTER TABLE `fabric_image_mappings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_fabric_image` (`fabric_id`,`image_asset_id`),
  ADD KEY `idx_fim_asset` (`image_asset_id`),
  ADD KEY `idx_fim_fabric_sort` (`fabric_id`,`sort_order`,`id`);

--
-- 表的索引 `fabric_materials`
--
ALTER TABLE `fabric_materials`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `fabric_code` (`fabric_code`),
  ADD KEY `idx_fabric_material` (`material_id`);

--
-- 表的索引 `fabric_product_families`
--
ALTER TABLE `fabric_product_families`
  ADD PRIMARY KEY (`fabric_id`,`sku_family_id`),
  ADD KEY `fk_fpf_sku_family` (`sku_family_id`);

--
-- 表的索引 `factory_contracts`
--
ALTER TABLE `factory_contracts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_fc_factory_contract` (`factory_id`,`contract_no`),
  ADD UNIQUE KEY `uq_fc_factory_order` (`factory_id`,`order_no`),
  ADD KEY `idx_fc_factory_id` (`factory_id`);

--
-- 表的索引 `factory_stock_inventory`
--
ALTER TABLE `factory_stock_inventory`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_fsi_op_factory` (`order_product_id`,`factory_id`),
  ADD KEY `fk_fsi_factory` (`factory_id`);

--
-- 表的索引 `factory_wip_inventory`
--
ALTER TABLE `factory_wip_inventory`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_fwi_op` (`order_product_id`),
  ADD KEY `idx_fwi_factory` (`factory_id`),
  ADD KEY `idx_fwi_contract_id` (`contract_id`);

--
-- 表的索引 `features`
--
ALTER TABLE `features`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `feature_categories`
--
ALTER TABLE `feature_categories`
  ADD PRIMARY KEY (`feature_id`,`category_id`),
  ADD KEY `fk_feature_category_category` (`category_id`);

--
-- 表的索引 `image_assets`
--
ALTER TABLE `image_assets`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_image_asset_sha256` (`sha256`),
  ADD UNIQUE KEY `uniq_image_asset_storage_path` (`storage_path`),
  ADD KEY `idx_image_asset_created_at` (`created_at`);

--
-- 表的索引 `image_types`
--
ALTER TABLE `image_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_image_type_name` (`name`),
  ADD KEY `idx_image_type_enabled_sort` (`is_enabled`,`sort_order`,`id`);

--
-- 表的索引 `image_type_platform_types`
--
ALTER TABLE `image_type_platform_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_itpt` (`image_type_id`,`platform_type_id`),
  ADD KEY `idx_itpt_type` (`image_type_id`),
  ADD KEY `idx_itpt_platform` (`platform_type_id`);

--
-- 表的索引 `logistics_destination_regions`
--
ALTER TABLE `logistics_destination_regions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `region_name` (`region_name`),
  ADD KEY `idx_region_sort_order` (`sort_order`,`id`);

--
-- 表的索引 `logistics_factories`
--
ALTER TABLE `logistics_factories`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `factory_name` (`factory_name`);

--
-- 表的索引 `logistics_forwarders`
--
ALTER TABLE `logistics_forwarders`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `forwarder_name` (`forwarder_name`);

--
-- 表的索引 `logistics_in_transit`
--
ALTER TABLE `logistics_in_transit`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_transit_box_no` (`logistics_box_no`),
  ADD UNIQUE KEY `uniq_transit_bl_no` (`bill_of_lading_no`),
  ADD KEY `idx_transit_factory` (`factory_id`),
  ADD KEY `idx_transit_forwarder` (`forwarder_id`),
  ADD KEY `idx_transit_wh` (`destination_warehouse_id`),
  ADD KEY `idx_transit_updated_id` (`updated_at`,`id`),
  ADD KEY `idx_transit_listed` (`listed_date`),
  ADD KEY `idx_transit_destination_region` (`destination_region_id`);

--
-- 表的索引 `logistics_in_transit_items`
--
ALTER TABLE `logistics_in_transit_items`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_transit_item` (`transit_id`,`order_product_id`),
  ADD KEY `idx_transit_item_transit` (`transit_id`),
  ADD KEY `idx_transit_item_order` (`order_product_id`);

--
-- 表的索引 `logistics_overseas_inventory`
--
ALTER TABLE `logistics_overseas_inventory`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_wh_order` (`warehouse_id`,`order_product_id`),
  ADD KEY `idx_inv_warehouse` (`warehouse_id`),
  ADD KEY `idx_inv_order_product` (`order_product_id`);

--
-- 表的索引 `logistics_overseas_warehouses`
--
ALTER TABLE `logistics_overseas_warehouses`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_wh_name` (`warehouse_name`),
  ADD UNIQUE KEY `uniq_wh_supplier_short` (`supplier_id`,`warehouse_short_name`),
  ADD KEY `idx_wh_region` (`region`),
  ADD KEY `idx_wh_enabled` (`is_enabled`),
  ADD KEY `idx_wh_destination_region` (`destination_region_id`);

--
-- 表的索引 `logistics_suppliers`
--
ALTER TABLE `logistics_suppliers`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `supplier_name` (`supplier_name`);

--
-- 表的索引 `materials`
--
ALTER TABLE `materials`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_material` (`material_type_id`,`name`),
  ADD KEY `idx_material_type_id` (`material_type_id`),
  ADD KEY `idx_material_parent` (`parent_id`);

--
-- 表的索引 `material_types`
--
ALTER TABLE `material_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `order_products`
--
ALTER TABLE `order_products`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `sku` (`sku`),
  ADD KEY `idx_sku_family` (`sku_family_id`),
  ADD KEY `idx_fabric` (`fabric_id`),
  ADD KEY `idx_source_order_product` (`source_order_product_id`);

--
-- 表的索引 `order_product_certifications`
--
ALTER TABLE `order_product_certifications`
  ADD PRIMARY KEY (`order_product_id`,`certification_id`),
  ADD KEY `fk_opc_certification` (`certification_id`);

--
-- 表的索引 `order_product_factory_links`
--
ALTER TABLE `order_product_factory_links`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_op_factory` (`order_product_id`,`factory_id`),
  ADD KEY `idx_op_factory_order_product` (`order_product_id`),
  ADD KEY `idx_op_factory_factory` (`factory_id`);

--
-- 表的索引 `order_product_features`
--
ALTER TABLE `order_product_features`
  ADD PRIMARY KEY (`order_product_id`,`feature_id`),
  ADD KEY `fk_opf_feature` (`feature_id`);

--
-- 表的索引 `order_product_materials`
--
ALTER TABLE `order_product_materials`
  ADD PRIMARY KEY (`order_product_id`,`material_id`),
  ADD KEY `fk_opm_material` (`material_id`);

--
-- 表的索引 `order_product_shipping_plans`
--
ALTER TABLE `order_product_shipping_plans`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_order_plan_name` (`order_product_id`,`plan_name`),
  ADD KEY `idx_ops_order` (`order_product_id`);

--
-- 表的索引 `order_product_shipping_plan_items`
--
ALTER TABLE `order_product_shipping_plan_items`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_opsi_unique` (`shipping_plan_id`,`substitute_order_product_id`,`sort_order`),
  ADD KEY `idx_opsi_plan` (`shipping_plan_id`),
  ADD KEY `fk_opsi_sub_order` (`substitute_order_product_id`);

--
-- 表的索引 `platform_types`
--
ALTER TABLE `platform_types`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- 表的索引 `product_categories`
--
ALTER TABLE `product_categories`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_category_cn` (`category_cn`),
  ADD UNIQUE KEY `uniq_category_en` (`category_en`);

--
-- 表的索引 `product_families`
--
ALTER TABLE `product_families`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `sku_family` (`sku_family`);

--
-- 表的索引 `sales_order_registrations`
--
ALTER TABLE `sales_order_registrations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sor_shop` (`shop_id`),
  ADD KEY `idx_sor_order_no` (`order_no`),
  ADD KEY `idx_sor_date` (`order_date`),
  ADD KEY `idx_sor_shop_order` (`shop_id`,`order_no`),
  ADD KEY `idx_sor_customer_name` (`customer_name`),
  ADD KEY `idx_sor_phone` (`phone`);

--
-- 表的索引 `sales_order_registration_logistics_items`
--
ALTER TABLE `sales_order_registration_logistics_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sorli_registration` (`registration_id`),
  ADD KEY `idx_sorli_tracking` (`tracking_no`(128)),
  ADD KEY `idx_sorli_carrier_tracking` (`shipping_carrier`,`tracking_no`(128)),
  ADD KEY `idx_sorli_registration_sort_id` (`registration_id`,`sort_order`,`id`);

--
-- 表的索引 `sales_order_registration_platform_items`
--
ALTER TABLE `sales_order_registration_platform_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sorpi_registration` (`registration_id`),
  ADD KEY `idx_sorpi_sales` (`sales_product_id`),
  ADD KEY `idx_sorpi_plan` (`shipping_plan_id`),
  ADD KEY `idx_sorpi_registration_id_id` (`registration_id`,`id`);

--
-- 表的索引 `sales_order_registration_shipment_items`
--
ALTER TABLE `sales_order_registration_shipment_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sorsi_registration` (`registration_id`),
  ADD KEY `idx_sorsi_order_product` (`order_product_id`),
  ADD KEY `idx_sorsi_plan` (`shipping_plan_id`),
  ADD KEY `idx_sorsi_registration_id_id` (`registration_id`,`id`);

--
-- 表的索引 `sales_parents`
--
ALTER TABLE `sales_parents`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_sales_parents_shop_parent_code` (`shop_id`,`parent_code`),
  ADD KEY `idx_parent_code` (`parent_code`),
  ADD KEY `idx_parent_shop` (`shop_id`);

--
-- 表的索引 `sales_products`
--
ALTER TABLE `sales_products`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_sales_products_shop_sku` (`shop_id`,`platform_sku`),
  ADD KEY `idx_sp_shop` (`shop_id`),
  ADD KEY `idx_sp_parent` (`parent_id`),
  ADD KEY `idx_sp_variant` (`variant_id`);

--
-- 表的索引 `sales_product_performances`
--
ALTER TABLE `sales_product_performances`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_sales_product_performance` (`sales_product_id`,`record_date`),
  ADD KEY `idx_sp_perf_date` (`record_date`),
  ADD KEY `idx_sp_perf_product` (`sales_product_id`);

--
-- 表的索引 `sales_product_variants`
--
ALTER TABLE `sales_product_variants`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_sales_product_variants_family_spec_fabric` (`sku_family_id`,`spec_name`,`fabric_id`),
  ADD KEY `idx_spv_sku_family` (`sku_family_id`),
  ADD KEY `idx_spv_fabric` (`fabric_id`);

--
-- 表的索引 `sales_variant_order_links`
--
ALTER TABLE `sales_variant_order_links`
  ADD PRIMARY KEY (`variant_id`,`order_product_id`),
  ADD KEY `fk_svol_order` (`order_product_id`);

--
-- 表的索引 `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`session_id`),
  ADD KEY `idx_emp` (`employee_id`);

--
-- 表的索引 `shops`
--
ALTER TABLE `shops`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_shop` (`shop_name`,`platform_type_id`,`brand_id`),
  ADD KEY `idx_shop_platform` (`platform_type_id`),
  ADD KEY `idx_shop_brand` (`brand_id`);

--
-- 表的索引 `sales_variant_image_mappings`
--
ALTER TABLE `sales_variant_image_mappings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_sim_variant_asset` (`variant_id`,`image_asset_id`),
  ADD KEY `idx_sku_images_asset` (`image_asset_id`),
  ADD KEY `idx_sim_variant` (`variant_id`),
  ADD KEY `idx_sim_variant_sort` (`variant_id`,`sort_order`,`id`);

--
-- 表的索引 `todos`
--
ALTER TABLE `todos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_due_date` (`due_date`),
  ADD KEY `idx_status` (`status`);

--
-- 表的索引 `todo_assignments`
--
ALTER TABLE `todo_assignments`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_todo_assignee` (`todo_id`,`assignee_id`),
  ADD KEY `idx_ta_assignee_todo` (`assignee_id`,`todo_id`);

--
-- 表的索引 `todo_sales_links`
--
ALTER TABLE `todo_sales_links`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_tsl_todo_sp` (`todo_id`,`sales_product_id`),
  ADD UNIQUE KEY `uniq_tsl_todo_sf` (`todo_id`,`sku_family_id`),
  ADD KEY `idx_tsl_todo` (`todo_id`),
  ADD KEY `idx_tsl_sales_product` (`sales_product_id`),
  ADD KEY `idx_tsl_sku_family` (`sku_family_id`);

--
-- 表的索引 `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `idx_username` (`username`);

--
-- 表的索引 `user_factory_scopes`
--
ALTER TABLE `user_factory_scopes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_user_factory_scope` (`user_id`,`factory_id`),
  ADD KEY `idx_user_factory_scope_user` (`user_id`),
  ADD KEY `idx_user_factory_scope_factory` (`factory_id`);

--
-- 在导出的表使用AUTO_INCREMENT
--

--
-- 使用表AUTO_INCREMENT `amazon_account_health`
--
ALTER TABLE `amazon_account_health`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_adjustments`
--
ALTER TABLE `amazon_ad_adjustments`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_deliveries`
--
ALTER TABLE `amazon_ad_deliveries`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_items`
--
ALTER TABLE `amazon_ad_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_operation_reasons`
--
ALTER TABLE `amazon_ad_operation_reasons`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_operation_types`
--
ALTER TABLE `amazon_ad_operation_types`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_products`
--
ALTER TABLE `amazon_ad_products`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_ad_subtypes`
--
ALTER TABLE `amazon_ad_subtypes`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_keywords`
--
ALTER TABLE `amazon_keywords`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `amazon_keyword_tags`
--
ALTER TABLE `amazon_keyword_tags`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `aplus_versions`
--
ALTER TABLE `aplus_versions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `aplus_version_assets`
--
ALTER TABLE `aplus_version_assets`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `brands`
--
ALTER TABLE `brands`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `certifications`
--
ALTER TABLE `certifications`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `fabric_image_mappings`
--
ALTER TABLE `fabric_image_mappings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `fabric_materials`
--
ALTER TABLE `fabric_materials`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `factory_contracts`
--
ALTER TABLE `factory_contracts`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `factory_stock_inventory`
--
ALTER TABLE `factory_stock_inventory`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `factory_wip_inventory`
--
ALTER TABLE `factory_wip_inventory`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `features`
--
ALTER TABLE `features`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `image_assets`
--
ALTER TABLE `image_assets`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `image_types`
--
ALTER TABLE `image_types`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `image_type_platform_types`
--
ALTER TABLE `image_type_platform_types`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_destination_regions`
--
ALTER TABLE `logistics_destination_regions`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_factories`
--
ALTER TABLE `logistics_factories`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_forwarders`
--
ALTER TABLE `logistics_forwarders`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_in_transit`
--
ALTER TABLE `logistics_in_transit`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_in_transit_items`
--
ALTER TABLE `logistics_in_transit_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_overseas_inventory`
--
ALTER TABLE `logistics_overseas_inventory`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_overseas_warehouses`
--
ALTER TABLE `logistics_overseas_warehouses`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `logistics_suppliers`
--
ALTER TABLE `logistics_suppliers`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `materials`
--
ALTER TABLE `materials`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `material_types`
--
ALTER TABLE `material_types`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `order_products`
--
ALTER TABLE `order_products`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `order_product_factory_links`
--
ALTER TABLE `order_product_factory_links`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `order_product_shipping_plans`
--
ALTER TABLE `order_product_shipping_plans`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `order_product_shipping_plan_items`
--
ALTER TABLE `order_product_shipping_plan_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `platform_types`
--
ALTER TABLE `platform_types`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `product_categories`
--
ALTER TABLE `product_categories`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `product_families`
--
ALTER TABLE `product_families`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_order_registrations`
--
ALTER TABLE `sales_order_registrations`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_order_registration_logistics_items`
--
ALTER TABLE `sales_order_registration_logistics_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_order_registration_platform_items`
--
ALTER TABLE `sales_order_registration_platform_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_order_registration_shipment_items`
--
ALTER TABLE `sales_order_registration_shipment_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_parents`
--
ALTER TABLE `sales_parents`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_products`
--
ALTER TABLE `sales_products`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_product_performances`
--
ALTER TABLE `sales_product_performances`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_product_variants`
--
ALTER TABLE `sales_product_variants`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `shops`
--
ALTER TABLE `shops`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `sales_variant_image_mappings`
--
ALTER TABLE `sales_variant_image_mappings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `todos`
--
ALTER TABLE `todos`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `todo_assignments`
--
ALTER TABLE `todo_assignments`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `todo_sales_links`
--
ALTER TABLE `todo_sales_links`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `users`
--
ALTER TABLE `users`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `user_factory_scopes`
--
ALTER TABLE `user_factory_scopes`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 限制导出的表
--

--
-- 限制表 `amazon_account_health`
--
ALTER TABLE `amazon_account_health`
  ADD CONSTRAINT `fk_aah_shop` FOREIGN KEY (`shop_id`) REFERENCES `shops` (`id`);

--
-- 限制表 `amazon_ad_adjustments`
--
ALTER TABLE `amazon_ad_adjustments`
  ADD CONSTRAINT `fk_ad_adjustment_item` FOREIGN KEY (`ad_item_id`) REFERENCES `amazon_ad_items` (`id`),
  ADD CONSTRAINT `fk_ad_adjustment_operation` FOREIGN KEY (`operation_type_id`) REFERENCES `amazon_ad_operation_types` (`id`),
  ADD CONSTRAINT `fk_ad_adjustment_reason` FOREIGN KEY (`reason_id`) REFERENCES `amazon_ad_operation_reasons` (`id`) ON DELETE SET NULL;

--
-- 限制表 `amazon_ad_deliveries`
--
ALTER TABLE `amazon_ad_deliveries`
  ADD CONSTRAINT `fk_ad_delivery_item` FOREIGN KEY (`ad_item_id`) REFERENCES `amazon_ad_items` (`id`) ON DELETE CASCADE;

--
-- 限制表 `amazon_ad_items`
--
ALTER TABLE `amazon_ad_items`
  ADD CONSTRAINT `fk_ad_campaign` FOREIGN KEY (`campaign_id`) REFERENCES `amazon_ad_items` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ad_portfolio` FOREIGN KEY (`portfolio_id`) REFERENCES `amazon_ad_items` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ad_sku` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_ad_subtype` FOREIGN KEY (`subtype_id`) REFERENCES `amazon_ad_subtypes` (`id`) ON DELETE SET NULL;

--
-- 限制表 `amazon_ad_operation_reasons`
--
ALTER TABLE `amazon_ad_operation_reasons`
  ADD CONSTRAINT `fk_ad_op_reason_type` FOREIGN KEY (`operation_type_id`) REFERENCES `amazon_ad_operation_types` (`id`) ON DELETE CASCADE;

--
-- 限制表 `amazon_ad_products`
--
ALTER TABLE `amazon_ad_products`
  ADD CONSTRAINT `fk_ad_product_item` FOREIGN KEY (`ad_item_id`) REFERENCES `amazon_ad_items` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ad_product_sales` FOREIGN KEY (`sales_product_id`) REFERENCES `sales_products` (`id`);

--
-- 限制表 `amazon_ad_subtype_operation_types`
--
ALTER TABLE `amazon_ad_subtype_operation_types`
  ADD CONSTRAINT `fk_ad_subtype_op_subtype` FOREIGN KEY (`subtype_id`) REFERENCES `amazon_ad_subtypes` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ad_subtype_op_type` FOREIGN KEY (`operation_type_id`) REFERENCES `amazon_ad_operation_types` (`id`) ON DELETE CASCADE;

--
-- 限制表 `amazon_keywords`
--
ALTER TABLE `amazon_keywords`
  ADD CONSTRAINT `fk_amazon_keyword_category` FOREIGN KEY (`category_id`) REFERENCES `product_categories` (`id`);

--
-- 限制表 `amazon_keyword_sku_rel`
--
ALTER TABLE `amazon_keyword_sku_rel`
  ADD CONSTRAINT `fk_keyword_sku_rel_keyword` FOREIGN KEY (`keyword_id`) REFERENCES `amazon_keywords` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_keyword_sku_rel_sku` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`) ON DELETE CASCADE;

--
-- 限制表 `amazon_keyword_tags`
--
ALTER TABLE `amazon_keyword_tags`
  ADD CONSTRAINT `fk_keyword_tag_category` FOREIGN KEY (`category_id`) REFERENCES `product_categories` (`id`) ON DELETE CASCADE;

--
-- 限制表 `amazon_keyword_tag_rel`
--
ALTER TABLE `amazon_keyword_tag_rel`
  ADD CONSTRAINT `fk_keyword_tag_rel_keyword` FOREIGN KEY (`keyword_id`) REFERENCES `amazon_keywords` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_keyword_tag_rel_tag` FOREIGN KEY (`tag_id`) REFERENCES `amazon_keyword_tags` (`id`) ON DELETE CASCADE;

--
-- 限制表 `fabric_image_mappings`
--
ALTER TABLE `fabric_image_mappings`
  ADD CONSTRAINT `fk_fim_asset` FOREIGN KEY (`image_asset_id`) REFERENCES `image_assets` (`id`),
  ADD CONSTRAINT `fk_fim_fabric` FOREIGN KEY (`fabric_id`) REFERENCES `fabric_materials` (`id`) ON DELETE CASCADE;

--
-- 限制表 `fabric_materials`
--
ALTER TABLE `fabric_materials`
  ADD CONSTRAINT `fk_fabric_material` FOREIGN KEY (`material_id`) REFERENCES `materials` (`id`) ON DELETE SET NULL;

--
-- 限制表 `fabric_product_families`
--
ALTER TABLE `fabric_product_families`
  ADD CONSTRAINT `fk_fpf_fabric` FOREIGN KEY (`fabric_id`) REFERENCES `fabric_materials` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_fpf_sku_family` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`) ON DELETE CASCADE;

--
-- 限制表 `factory_contracts`
--
ALTER TABLE `factory_contracts`
  ADD CONSTRAINT `fk_fc_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`);

--
-- 限制表 `factory_stock_inventory`
--
ALTER TABLE `factory_stock_inventory`
  ADD CONSTRAINT `fk_fsi_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`),
  ADD CONSTRAINT `fk_fsi_op` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `factory_wip_inventory`
--
ALTER TABLE `factory_wip_inventory`
  ADD CONSTRAINT `fk_fwi_contract` FOREIGN KEY (`contract_id`) REFERENCES `factory_contracts` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_fwi_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`),
  ADD CONSTRAINT `fk_fwi_op` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `feature_categories`
--
ALTER TABLE `feature_categories`
  ADD CONSTRAINT `fk_feature_category_category` FOREIGN KEY (`category_id`) REFERENCES `product_categories` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_feature_category_feature` FOREIGN KEY (`feature_id`) REFERENCES `features` (`id`) ON DELETE CASCADE;

--
-- 限制表 `logistics_in_transit`
--
ALTER TABLE `logistics_in_transit`
  ADD CONSTRAINT `fk_transit_destination_region` FOREIGN KEY (`destination_region_id`) REFERENCES `logistics_destination_regions` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_transit_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`),
  ADD CONSTRAINT `fk_transit_forwarder` FOREIGN KEY (`forwarder_id`) REFERENCES `logistics_forwarders` (`id`),
  ADD CONSTRAINT `fk_transit_wh` FOREIGN KEY (`destination_warehouse_id`) REFERENCES `logistics_overseas_warehouses` (`id`) ON DELETE SET NULL;

--
-- 限制表 `logistics_in_transit_items`
--
ALTER TABLE `logistics_in_transit_items`
  ADD CONSTRAINT `fk_transit_item_order` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`),
  ADD CONSTRAINT `fk_transit_item_transit` FOREIGN KEY (`transit_id`) REFERENCES `logistics_in_transit` (`id`) ON DELETE CASCADE;

--
-- 限制表 `logistics_overseas_inventory`
--
ALTER TABLE `logistics_overseas_inventory`
  ADD CONSTRAINT `fk_inv_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_inv_warehouse` FOREIGN KEY (`warehouse_id`) REFERENCES `logistics_overseas_warehouses` (`id`) ON DELETE CASCADE;

--
-- 限制表 `logistics_overseas_warehouses`
--
ALTER TABLE `logistics_overseas_warehouses`
  ADD CONSTRAINT `fk_wh_destination_region` FOREIGN KEY (`destination_region_id`) REFERENCES `logistics_destination_regions` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_wh_supplier` FOREIGN KEY (`supplier_id`) REFERENCES `logistics_suppliers` (`id`);

--
-- 限制表 `materials`
--
ALTER TABLE `materials`
  ADD CONSTRAINT `fk_material_parent` FOREIGN KEY (`parent_id`) REFERENCES `materials` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_material_type` FOREIGN KEY (`material_type_id`) REFERENCES `material_types` (`id`);

--
-- 限制表 `order_products`
--
ALTER TABLE `order_products`
  ADD CONSTRAINT `fk_order_products_fabric` FOREIGN KEY (`fabric_id`) REFERENCES `fabric_materials` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_order_products_sku_family` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_order_products_source` FOREIGN KEY (`source_order_product_id`) REFERENCES `order_products` (`id`) ON DELETE SET NULL;

--
-- 限制表 `order_product_certifications`
--
ALTER TABLE `order_product_certifications`
  ADD CONSTRAINT `fk_opc_certification` FOREIGN KEY (`certification_id`) REFERENCES `certifications` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_opc_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `order_product_factory_links`
--
ALTER TABLE `order_product_factory_links`
  ADD CONSTRAINT `fk_opfl_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_opfl_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `order_product_features`
--
ALTER TABLE `order_product_features`
  ADD CONSTRAINT `fk_opf_feature` FOREIGN KEY (`feature_id`) REFERENCES `features` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_opf_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `order_product_materials`
--
ALTER TABLE `order_product_materials`
  ADD CONSTRAINT `fk_opm_material` FOREIGN KEY (`material_id`) REFERENCES `materials` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_opm_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `order_product_shipping_plans`
--
ALTER TABLE `order_product_shipping_plans`
  ADD CONSTRAINT `fk_ops_order` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `order_product_shipping_plan_items`
--
ALTER TABLE `order_product_shipping_plan_items`
  ADD CONSTRAINT `fk_opsi_plan` FOREIGN KEY (`shipping_plan_id`) REFERENCES `order_product_shipping_plans` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_opsi_sub_order` FOREIGN KEY (`substitute_order_product_id`) REFERENCES `order_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `sales_order_registrations`
--
ALTER TABLE `sales_order_registrations`
  ADD CONSTRAINT `fk_sor_shop` FOREIGN KEY (`shop_id`) REFERENCES `shops` (`id`) ON DELETE SET NULL;

--
-- 限制表 `sales_order_registration_logistics_items`
--
ALTER TABLE `sales_order_registration_logistics_items`
  ADD CONSTRAINT `fk_sorli_registration` FOREIGN KEY (`registration_id`) REFERENCES `sales_order_registrations` (`id`) ON DELETE CASCADE;

--
-- 限制表 `sales_order_registration_platform_items`
--
ALTER TABLE `sales_order_registration_platform_items`
  ADD CONSTRAINT `fk_sorpi_plan` FOREIGN KEY (`shipping_plan_id`) REFERENCES `order_product_shipping_plans` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_sorpi_registration` FOREIGN KEY (`registration_id`) REFERENCES `sales_order_registrations` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_sorpi_sales` FOREIGN KEY (`sales_product_id`) REFERENCES `sales_products` (`id`) ON DELETE SET NULL;

--
-- 限制表 `sales_order_registration_shipment_items`
--
ALTER TABLE `sales_order_registration_shipment_items`
  ADD CONSTRAINT `fk_sorsi_order_product` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_sorsi_plan` FOREIGN KEY (`shipping_plan_id`) REFERENCES `order_product_shipping_plans` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_sorsi_registration` FOREIGN KEY (`registration_id`) REFERENCES `sales_order_registrations` (`id`) ON DELETE CASCADE;

--
-- 限制表 `sales_parents`
--
ALTER TABLE `sales_parents`
  ADD CONSTRAINT `fk_sales_parents_shop` FOREIGN KEY (`shop_id`) REFERENCES `shops` (`id`) ON DELETE SET NULL;

--
-- 限制表 `sales_products`
--
ALTER TABLE `sales_products`
  ADD CONSTRAINT `fk_sp_parent` FOREIGN KEY (`parent_id`) REFERENCES `sales_parents` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_sp_shop` FOREIGN KEY (`shop_id`) REFERENCES `shops` (`id`),
  ADD CONSTRAINT `fk_sp_variant` FOREIGN KEY (`variant_id`) REFERENCES `sales_product_variants` (`id`);

--
-- 限制表 `sales_product_performances`
--
ALTER TABLE `sales_product_performances`
  ADD CONSTRAINT `fk_sp_perf_sales_product` FOREIGN KEY (`sales_product_id`) REFERENCES `sales_products` (`id`) ON DELETE CASCADE;

--
-- 限制表 `sales_product_variants`
--
ALTER TABLE `sales_product_variants`
  ADD CONSTRAINT `fk_spv_fabric` FOREIGN KEY (`fabric_id`) REFERENCES `fabric_materials` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_spv_sku_family` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`);

--
-- 限制表 `sales_variant_order_links`
--
ALTER TABLE `sales_variant_order_links`
  ADD CONSTRAINT `fk_svol_order` FOREIGN KEY (`order_product_id`) REFERENCES `order_products` (`id`),
  ADD CONSTRAINT `fk_svol_variant` FOREIGN KEY (`variant_id`) REFERENCES `sales_product_variants` (`id`) ON DELETE CASCADE;

--
-- 限制表 `sessions`
--
ALTER TABLE `sessions`
  ADD CONSTRAINT `fk_sessions_user` FOREIGN KEY (`employee_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- 限制表 `shops`
--
ALTER TABLE `shops`
  ADD CONSTRAINT `fk_shop_brand` FOREIGN KEY (`brand_id`) REFERENCES `brands` (`id`),
  ADD CONSTRAINT `fk_shop_platform_type` FOREIGN KEY (`platform_type_id`) REFERENCES `platform_types` (`id`);

--
-- 限制表 `sales_variant_image_mappings`
--
ALTER TABLE `sales_variant_image_mappings`
  ADD CONSTRAINT `fk_sim_variant` FOREIGN KEY (`variant_id`) REFERENCES `sales_product_variants` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_sku_image_asset` FOREIGN KEY (`image_asset_id`) REFERENCES `image_assets` (`id`);

--
-- 限制表 `todo_assignments`
--
ALTER TABLE `todo_assignments`
  ADD CONSTRAINT `fk_ta_assignee` FOREIGN KEY (`assignee_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ta_todo` FOREIGN KEY (`todo_id`) REFERENCES `todos` (`id`) ON DELETE CASCADE;

--
-- 限制表 `todo_sales_links`
--
ALTER TABLE `todo_sales_links`
  ADD CONSTRAINT `fk_tsl_sales_product` FOREIGN KEY (`sales_product_id`) REFERENCES `sales_products` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_tsl_sku_family` FOREIGN KEY (`sku_family_id`) REFERENCES `product_families` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_tsl_todo` FOREIGN KEY (`todo_id`) REFERENCES `todos` (`id`) ON DELETE CASCADE;

--
-- 限制表 `user_factory_scopes`
--
ALTER TABLE `user_factory_scopes`
  ADD CONSTRAINT `fk_ufs_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ufs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

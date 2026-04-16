-- Schema baseline extracted from runtime CREATE TABLE definitions
-- Generated: 2026-04-01
SET NAMES utf8mb4;

-- ----------------------------
-- Table: amazon_account_health
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_account_health (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NOT NULL,
            account_health_rating INT NOT NULL,
            suspected_ip_infringement INT NOT NULL DEFAULT 0,
            intellectual_property_complaints INT NOT NULL DEFAULT 0,
            authenticity_customer_complaints INT NOT NULL DEFAULT 0,
            condition_customer_complaints INT NOT NULL DEFAULT 0,
            food_safety_issues INT NOT NULL DEFAULT 0,
            listing_policy_violations INT NOT NULL DEFAULT 0,
            restricted_product_policy_violations INT NOT NULL DEFAULT 0,
            customer_review_policy_violations INT NOT NULL DEFAULT 0,
            other_policy_violations INT NOT NULL DEFAULT 0,
            regulatory_compliance_issues INT NOT NULL DEFAULT 0,
            order_defect_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            negative_feedback_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            a_to_z_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            chargeback_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            late_shipment_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            pre_fulfillment_cancel_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            valid_tracking_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            on_time_delivery_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            record_datetime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            remark VARCHAR(500) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_aah_shop_date (shop_id, record_datetime),
            INDEX idx_aah_record_datetime (record_datetime),
            CONSTRAINT fk_aah_shop FOREIGN KEY (shop_id)
                REFERENCES shops(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_adjustments
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_adjustments (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            adjust_date DATETIME NOT NULL,
            ad_item_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            target_object VARCHAR(255) NOT NULL,
            before_value VARCHAR(64) NULL,
            after_value VARCHAR(64) NULL,
            reason_id INT UNSIGNED NULL,
            start_time DATETIME NULL,
            end_time DATETIME NULL,
            impressions VARCHAR(32) NULL,
            clicks VARCHAR(32) NULL,
            cost VARCHAR(32) NULL,
            orders VARCHAR(32) NULL,
            sales VARCHAR(32) NULL,
            acos VARCHAR(32) NULL,
            cpc VARCHAR(32) NULL,
            ctr VARCHAR(32) NULL,
            cvr VARCHAR(32) NULL,
            attribution_checked TINYINT(1) NOT NULL DEFAULT 0,
            attribution_orders VARCHAR(32) NULL,
            attribution_sales VARCHAR(32) NULL,
            remark VARCHAR(255) NULL,
            is_quick_submit TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ad_adjustment_ad_item (ad_item_id),
            INDEX idx_ad_adjustment_operation (operation_type_id),
            INDEX idx_ad_adjustment_reason (reason_id),
            INDEX idx_ad_adjustment_date (adjust_date),
            CONSTRAINT fk_ad_adjustment_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE RESTRICT,
            CONSTRAINT fk_ad_adjustment_operation FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_ad_adjustment_reason FOREIGN KEY (reason_id)
                REFERENCES amazon_ad_operation_reasons(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_deliveries
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_deliveries (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            status VARCHAR(16) NOT NULL DEFAULT '启动',
            ad_item_id INT UNSIGNED NOT NULL,
            delivery_desc VARCHAR(255) NOT NULL,
            bid_value VARCHAR(32) NULL,
            observe_interval VARCHAR(64) NULL,
            next_observe_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_delivery_item (ad_item_id),
            INDEX idx_ad_delivery_status (status),
            INDEX idx_ad_delivery_next_observe (next_observe_at),
            CONSTRAINT fk_ad_delivery_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ad_level VARCHAR(16) NOT NULL,
            sku_family_id INT UNSIGNED NULL,
            portfolio_id INT UNSIGNED NULL,
            campaign_id INT UNSIGNED NULL,
            strategy_code VARCHAR(8) NULL,
            subtype_id INT UNSIGNED NULL,
            name VARCHAR(255) NOT NULL,
            is_shared_budget TINYINT(1) NULL,
            status VARCHAR(16) NULL,
            budget DECIMAL(12,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_level (ad_level),
            INDEX idx_ad_sku (sku_family_id),
            INDEX idx_ad_portfolio (portfolio_id),
            INDEX idx_ad_campaign (campaign_id),
            INDEX idx_ad_subtype (subtype_id),
            CONSTRAINT fk_ad_sku FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_ad_portfolio FOREIGN KEY (portfolio_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_campaign FOREIGN KEY (campaign_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_operation_reasons
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_operation_reasons (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            operation_type_id INT UNSIGNED NOT NULL,
            reason_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_op_reason (operation_type_id, reason_name),
            INDEX idx_ad_op_reason_type (operation_type_id),
            CONSTRAINT fk_ad_op_reason_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_operation_types
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_operation_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            apply_portfolio TINYINT(1) NOT NULL DEFAULT 1,
            apply_campaign TINYINT(1) NOT NULL DEFAULT 1,
            apply_group TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_products
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            status VARCHAR(16) NOT NULL DEFAULT '启动',
            ad_item_id INT UNSIGNED NOT NULL,
            sales_product_id INT UNSIGNED NOT NULL,
            observe_interval VARCHAR(64) NULL,
            next_observe_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_product_item (ad_item_id),
            INDEX idx_ad_product_sales (sales_product_id),
            INDEX idx_ad_product_status (status),
            INDEX idx_ad_product_next_observe (next_observe_at),
            CONSTRAINT fk_ad_product_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_product_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_subtype_operation_types
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_subtype_operation_types (
            subtype_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (subtype_id, operation_type_id),
            CONSTRAINT fk_ad_subtype_op_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype_op_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_ad_subtypes
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_ad_subtypes (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            description VARCHAR(255) NOT NULL,
            ad_class VARCHAR(8) NOT NULL DEFAULT 'SP',
            subtype_code VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_subtype (ad_class, subtype_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_keyword_sku_rel
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_keyword_sku_rel (
            keyword_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            relevance_score TINYINT UNSIGNED NOT NULL DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (keyword_id, sku_family_id),
            INDEX idx_keyword_sku_rel_sku (sku_family_id),
            CONSTRAINT fk_keyword_sku_rel_keyword FOREIGN KEY (keyword_id)
                REFERENCES amazon_keywords(id) ON DELETE CASCADE,
            CONSTRAINT fk_keyword_sku_rel_sku FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_keyword_tag_rel
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_keyword_tag_rel (
            keyword_id INT UNSIGNED NOT NULL,
            tag_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (keyword_id, tag_id),
            CONSTRAINT fk_keyword_tag_rel_keyword FOREIGN KEY (keyword_id)
                REFERENCES amazon_keywords(id) ON DELETE CASCADE,
            CONSTRAINT fk_keyword_tag_rel_tag FOREIGN KEY (tag_id)
                REFERENCES amazon_keyword_tags(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_keyword_tags
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_keyword_tags (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_id INT UNSIGNED NOT NULL,
            tag_name VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_keyword_tag (category_id, tag_name),
            INDEX idx_keyword_tag_category (category_id),
            CONSTRAINT fk_keyword_tag_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: amazon_keywords
-- ----------------------------
CREATE TABLE IF NOT EXISTS amazon_keywords (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_id INT UNSIGNED NOT NULL,
            user_search_term VARCHAR(255) NOT NULL,
            search_rank INT NULL,
            rank_updated_at DATETIME NULL,
            previous_search_rank INT NULL,
            previous_rank_updated_at DATETIME NULL,
            top_click_asin1 VARCHAR(64) NULL,
            top_click_asin1_click_share VARCHAR(32) NULL,
            top_click_asin1_conversion_share VARCHAR(32) NULL,
            top_click_asin2 VARCHAR(64) NULL,
            top_click_asin2_click_share VARCHAR(32) NULL,
            top_click_asin2_conversion_share VARCHAR(32) NULL,
            top_click_asin3 VARCHAR(64) NULL,
            top_click_asin3_click_share VARCHAR(32) NULL,
            top_click_asin3_conversion_share VARCHAR(32) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_amazon_keyword_term (user_search_term),
            INDEX idx_amazon_keyword_category (category_id),
            INDEX idx_amazon_keyword_rank_updated (rank_updated_at),
            CONSTRAINT fk_amazon_keyword_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: brands
-- ----------------------------
CREATE TABLE IF NOT EXISTS brands (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: certifications
-- ----------------------------
CREATE TABLE IF NOT EXISTS certifications (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(128) NOT NULL UNIQUE,
                icon_name VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: fabric_images
-- ----------------------------
CREATE TABLE IF NOT EXISTS fabric_images (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            fabric_id INT UNSIGNED NOT NULL,
            image_name VARCHAR(255) NOT NULL,
            sort_order INT UNSIGNED NOT NULL DEFAULT 0,
            remark VARCHAR(50) NULL DEFAULT NULL COMMENT '备注类型：平面原图/褶皱原图/卖点图',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_images_fabric (fabric_id),
            INDEX idx_fabric_images_sort (fabric_id, sort_order),
            CONSTRAINT fk_fabric_images_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: fabric_materials
-- ----------------------------
CREATE TABLE IF NOT EXISTS fabric_materials (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            fabric_code VARCHAR(64) NOT NULL UNIQUE,
            fabric_name_en VARCHAR(128) NOT NULL,
            representative_color VARCHAR(7) NULL,
            material_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_material (material_id),
            CONSTRAINT fk_fabric_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: fabric_product_families
-- ----------------------------
CREATE TABLE IF NOT EXISTS fabric_product_families (
            fabric_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (fabric_id, sku_family_id),
            CONSTRAINT fk_fpf_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE CASCADE,
            CONSTRAINT fk_fpf_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: factory_stock_inventory
-- ----------------------------
CREATE TABLE IF NOT EXISTS factory_stock_inventory (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            order_product_id INT UNSIGNED NOT NULL,
            factory_id INT UNSIGNED NOT NULL,
            quantity INT NOT NULL DEFAULT 0,
            notes TEXT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_fsi_op_factory (order_product_id, factory_id),
            CONSTRAINT fk_fsi_op FOREIGN KEY (order_product_id) REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_fsi_factory FOREIGN KEY (factory_id) REFERENCES logistics_factories(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: factory_wip_inventory
-- ----------------------------
CREATE TABLE IF NOT EXISTS factory_wip_inventory (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            order_product_id INT UNSIGNED NOT NULL,
            factory_id INT UNSIGNED NOT NULL,
            quantity INT NOT NULL DEFAULT 0,
            expected_completion_date DATE NULL,
            is_completed TINYINT(1) NOT NULL DEFAULT 0,
            actual_completion_date DATE NULL,
            notes TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_fwi_op (order_product_id),
            KEY idx_fwi_factory (factory_id),
            CONSTRAINT fk_fwi_op FOREIGN KEY (order_product_id) REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_fwi_factory FOREIGN KEY (factory_id) REFERENCES logistics_factories(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: feature_categories
-- ----------------------------
CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: features
-- ----------------------------
CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_destination_regions
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_destination_regions (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            region_name VARCHAR(64) NOT NULL UNIQUE,
            sort_order INT UNSIGNED NOT NULL DEFAULT 100,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_factories
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_factories (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            factory_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_forwarders
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_forwarders (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            forwarder_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_in_transit
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_in_transit (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            factory_id INT UNSIGNED NOT NULL,
            factory_ship_date_initial DATE NULL,
            factory_ship_date_previous DATE NULL,
            factory_ship_date_latest DATE NULL,
            forwarder_id INT UNSIGNED NULL,
            logistics_box_no VARCHAR(128) NULL,
            customs_clearance_no VARCHAR(128) NOT NULL,
            etd_initial DATE NULL,
            etd_previous DATE NULL,
            etd_latest DATE NULL,
            eta_initial DATE NULL,
            eta_previous DATE NULL,
            eta_latest DATE NULL,
            arrival_port_date DATE NULL,
            expected_warehouse_date DATE NULL,
            expected_listed_date_initial DATE NULL,
            expected_listed_date_latest DATE NULL,
            listed_date DATE NULL,
            shipping_company VARCHAR(128) NULL,
            vessel_voyage VARCHAR(128) NULL,
            bill_of_lading_no VARCHAR(128) NULL,
            declaration_docs_provided TINYINT(1) NOT NULL DEFAULT 0,
            inventory_registered TINYINT(1) NOT NULL DEFAULT 0,
            clearance_docs_provided TINYINT(1) NOT NULL DEFAULT 0,
            qty_verified TINYINT(1) NOT NULL DEFAULT 0,
            qty_consistent TINYINT(1) NOT NULL DEFAULT 0,
            financial_verified TINYINT(1) NOT NULL DEFAULT 0,
            port_of_loading VARCHAR(128) NULL,
            port_of_destination VARCHAR(128) NULL,
            destination_region_id INT UNSIGNED NULL,
            destination_warehouse_id INT UNSIGNED NULL,
            confirmed_boxed_qty TINYINT(1) NOT NULL DEFAULT 0,
            inbound_order_no VARCHAR(128) NULL,
            remark TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_transit_box_no (logistics_box_no),
            UNIQUE KEY uniq_transit_customs_no (customs_clearance_no),
            UNIQUE KEY uniq_transit_bl_no (bill_of_lading_no),
            INDEX idx_transit_factory (factory_id),
            INDEX idx_transit_forwarder (forwarder_id),
            INDEX idx_transit_destination_region (destination_region_id),
            INDEX idx_transit_wh (destination_warehouse_id),
            CONSTRAINT fk_transit_factory FOREIGN KEY (factory_id)
                REFERENCES logistics_factories(id) ON DELETE RESTRICT,
            CONSTRAINT fk_transit_forwarder FOREIGN KEY (forwarder_id)
                REFERENCES logistics_forwarders(id) ON DELETE SET NULL,
            CONSTRAINT fk_transit_destination_region FOREIGN KEY (destination_region_id)
                REFERENCES logistics_destination_regions(id) ON DELETE SET NULL,
            CONSTRAINT fk_transit_wh FOREIGN KEY (destination_warehouse_id)
                REFERENCES logistics_overseas_warehouses(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_in_transit_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_in_transit_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            transit_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NOT NULL,
            shipped_qty INT NOT NULL DEFAULT 0,
            listed_qty INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_transit_item (transit_id, order_product_id),
            INDEX idx_transit_item_transit (transit_id),
            INDEX idx_transit_item_order (order_product_id),
            CONSTRAINT fk_transit_item_transit FOREIGN KEY (transit_id)
                REFERENCES logistics_in_transit(id) ON DELETE CASCADE,
            CONSTRAINT fk_transit_item_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_overseas_inventory
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_overseas_inventory (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            warehouse_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NOT NULL,
            available_qty INT NOT NULL DEFAULT 0,
            in_transit_qty INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_wh_order (warehouse_id, order_product_id),
            INDEX idx_inv_warehouse (warehouse_id),
            INDEX idx_inv_order_product (order_product_id),
            CONSTRAINT fk_inv_warehouse FOREIGN KEY (warehouse_id)
                REFERENCES logistics_overseas_warehouses(id) ON DELETE CASCADE,
            CONSTRAINT fk_inv_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_overseas_warehouses
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_overseas_warehouses (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            warehouse_name VARCHAR(255) NOT NULL,
            supplier_id INT UNSIGNED NOT NULL,
            warehouse_short_name VARCHAR(128) NOT NULL,
            is_enabled TINYINT(1) NOT NULL DEFAULT 1,
            region VARCHAR(64) NULL,
            destination_region_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_wh_name (warehouse_name),
            UNIQUE KEY uniq_wh_supplier_short (supplier_id, warehouse_short_name),
            INDEX idx_wh_region (region),
            INDEX idx_wh_destination_region (destination_region_id),
            INDEX idx_wh_enabled (is_enabled),
            CONSTRAINT fk_wh_supplier FOREIGN KEY (supplier_id)
                REFERENCES logistics_suppliers(id) ON DELETE RESTRICT,
            CONSTRAINT fk_wh_destination_region FOREIGN KEY (destination_region_id)
                REFERENCES logistics_destination_regions(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: logistics_suppliers
-- ----------------------------
CREATE TABLE IF NOT EXISTS logistics_suppliers (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            supplier_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: material_types
-- ----------------------------
CREATE TABLE IF NOT EXISTS material_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: materials
-- ----------------------------
CREATE TABLE IF NOT EXISTS materials (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            material_type_id INT UNSIGNED NOT NULL,
            parent_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_material (material_type_id, name),
            INDEX idx_material_type_id (material_type_id),
            INDEX idx_material_parent (parent_id),
            CONSTRAINT fk_material_type FOREIGN KEY (material_type_id)
                REFERENCES material_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_material_parent FOREIGN KEY (parent_id)
                REFERENCES materials(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_product_certifications
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_product_certifications (
            order_product_id INT UNSIGNED NOT NULL,
            certification_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, certification_id),
            CONSTRAINT fk_opc_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opc_certification FOREIGN KEY (certification_id)
                REFERENCES certifications(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_product_features
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_product_features (
            order_product_id INT UNSIGNED NOT NULL,
            feature_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, feature_id),
            CONSTRAINT fk_opf_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opf_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_product_materials
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_product_materials (
            order_product_id INT UNSIGNED NOT NULL,
            material_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, material_id),
            CONSTRAINT fk_opm_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opm_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_product_shipping_plan_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_product_shipping_plan_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shipping_plan_id INT UNSIGNED NOT NULL,
            substitute_order_product_id INT UNSIGNED NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            sort_order INT UNSIGNED NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_opsi_unique (shipping_plan_id, substitute_order_product_id, sort_order),
            INDEX idx_opsi_plan (shipping_plan_id),
            CONSTRAINT fk_opsi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE CASCADE,
            CONSTRAINT fk_opsi_sub_order FOREIGN KEY (substitute_order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_product_shipping_plans
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_product_shipping_plans (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            order_product_id INT UNSIGNED NOT NULL,
            plan_name VARCHAR(128) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_order_plan_name (order_product_id, plan_name),
            INDEX idx_ops_order (order_product_id),
            CONSTRAINT fk_ops_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: order_products
-- ----------------------------
CREATE TABLE IF NOT EXISTS order_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku VARCHAR(64) NOT NULL UNIQUE,
            sku_family_id INT UNSIGNED NULL,
            version_no VARCHAR(64) NOT NULL,
            fabric_id INT UNSIGNED NULL,
            spec_qty_short VARCHAR(128) NOT NULL,
            contents_desc_en VARCHAR(255) NULL,
            is_iteration TINYINT(1) NOT NULL DEFAULT 0,
            is_dachene_product TINYINT(1) NOT NULL DEFAULT 0,
            is_on_market TINYINT(1) NOT NULL DEFAULT 1,
            source_order_product_id INT UNSIGNED NULL,
            finished_length_in DECIMAL(10,2) NULL,
            finished_width_in DECIMAL(10,2) NULL,
            finished_height_in DECIMAL(10,2) NULL,
            net_weight_lbs DECIMAL(10,2) NULL,
            package_length_in DECIMAL(10,2) NULL,
            package_width_in DECIMAL(10,2) NULL,
            package_height_in DECIMAL(10,2) NULL,
            gross_weight_lbs DECIMAL(10,2) NULL,
            cost_usd DECIMAL(10,2) NULL,
            carton_qty INT UNSIGNED NULL,
            package_size_class VARCHAR(64) NULL,
            last_mile_avg_freight_usd DECIMAL(10,2) NULL,
            factory_wip_stock INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sku_family (sku_family_id),
            INDEX idx_fabric (fabric_id),
            INDEX idx_source_order_product (source_order_product_id),
            CONSTRAINT fk_order_products_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_source FOREIGN KEY (source_order_product_id)
                REFERENCES order_products(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: platform_types
-- ----------------------------
CREATE TABLE IF NOT EXISTS platform_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: product_categories
-- ----------------------------
CREATE TABLE IF NOT EXISTS product_categories (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_cn VARCHAR(64) NOT NULL,
            category_en VARCHAR(64) NOT NULL,
            category_en_name VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_category_cn (category_cn),
            UNIQUE KEY uniq_category_en (category_en)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: product_families
-- ----------------------------
CREATE TABLE IF NOT EXISTS product_families (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku_family VARCHAR(64) NOT NULL UNIQUE,
            category VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_order_registration_logistics_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_order_registration_logistics_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            shipping_carrier VARCHAR(128) NULL,
            tracking_no VARCHAR(255) NULL,
            sort_order INT UNSIGNED NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorli_registration (registration_id),
            INDEX idx_sorli_tracking (tracking_no(128)),
            CONSTRAINT fk_sorli_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_order_registration_platform_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_order_registration_platform_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            sales_product_id INT UNSIGNED NULL,
            platform_sku VARCHAR(128) NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            shipping_plan_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorpi_registration (registration_id),
            INDEX idx_sorpi_sales (sales_product_id),
            INDEX idx_sorpi_plan (shipping_plan_id),
            CONSTRAINT fk_sorpi_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE,
            CONSTRAINT fk_sorpi_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE SET NULL,
            CONSTRAINT fk_sorpi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_order_registration_shipment_items
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_order_registration_shipment_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NULL,
            order_sku VARCHAR(64) NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            source_type VARCHAR(16) NOT NULL DEFAULT 'manual',
            shipping_plan_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorsi_registration (registration_id),
            INDEX idx_sorsi_order_product (order_product_id),
            INDEX idx_sorsi_plan (shipping_plan_id),
            CONSTRAINT fk_sorsi_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE,
            CONSTRAINT fk_sorsi_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE SET NULL,
            CONSTRAINT fk_sorsi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_order_registrations
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_order_registrations (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NULL,
            order_no VARCHAR(128) NOT NULL,
            order_date DATE NULL,
            customer_name VARCHAR(128) NULL,
            phone VARCHAR(64) NULL,
            zip_code VARCHAR(16) NULL,
            address VARCHAR(255) NULL,
            city VARCHAR(64) NULL,
            state VARCHAR(32) NULL,
            shipping_status VARCHAR(32) NOT NULL DEFAULT 'pending',
            is_review_invited TINYINT(1) NOT NULL DEFAULT 0,
            is_logistics_emailed TINYINT(1) NOT NULL DEFAULT 0,
            compensation_action VARCHAR(255) NULL,
            remark TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sor_shop (shop_id),
            INDEX idx_sor_order_no (order_no),
            INDEX idx_sor_date (order_date),
            CONSTRAINT fk_sor_shop FOREIGN KEY (shop_id)
                REFERENCES shops(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_parents
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_parents (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                parent_code VARCHAR(64) NOT NULL UNIQUE,
                is_enabled TINYINT(1) NOT NULL DEFAULT 1,
                shop_id INT UNSIGNED NULL,
                sku_marker VARCHAR(128) NULL,
                estimated_refund_rate DECIMAL(8,4) NULL,
                estimated_discount_rate DECIMAL(8,4) NULL,
                commission_rate DECIMAL(8,4) NULL,
                estimated_acoas DECIMAL(8,4) NULL,
                sales_title VARCHAR(200) NULL,
                sales_intro VARCHAR(500) NULL,
                sales_bullet_1 VARCHAR(500) NULL,
                sales_bullet_2 VARCHAR(500) NULL,
                sales_bullet_3 VARCHAR(500) NULL,
                sales_bullet_4 VARCHAR(500) NULL,
                sales_bullet_5 VARCHAR(500) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_parent_code (parent_code),
                INDEX idx_parent_shop (shop_id),
                CONSTRAINT fk_sales_parents_shop FOREIGN KEY (shop_id)
                    REFERENCES shops(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_product_order_links
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_product_order_links (
            sales_product_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            PRIMARY KEY (sales_product_id, order_product_id),
            CONSTRAINT fk_spol_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_spol_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sales_products
-- ----------------------------
CREATE TABLE IF NOT EXISTS sales_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NULL,
            portfolio_id INT UNSIGNED NOT NULL,
            platform_sku VARCHAR(128) NOT NULL UNIQUE,
            product_status VARCHAR(16) NOT NULL DEFAULT 'enabled',
            sku_family_id INT UNSIGNED NULL,
            parent_id INT UNSIGNED NULL,
            child_code VARCHAR(64) NULL,
            dachene_yuncang_no VARCHAR(128) NULL,
            fabric VARCHAR(255) NULL,
            spec_name VARCHAR(255) NULL,
            sales_title VARCHAR(200) NULL,
            sale_price_usd DECIMAL(10,2) NULL,
            warehouse_cost_usd DECIMAL(10,2) NULL,
            last_mile_cost_usd DECIMAL(10,2) NULL,
            package_length_in DECIMAL(10,2) NULL,
            package_width_in DECIMAL(10,2) NULL,
            package_height_in DECIMAL(10,2) NULL,
            net_weight_lbs DECIMAL(10,2) NULL,
            gross_weight_lbs DECIMAL(10,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sp_shop (shop_id),
            INDEX idx_sp_sku_family (sku_family_id),
            INDEX idx_sp_parent (parent_id),
            INDEX idx_sp_portfolio (portfolio_id),
            CONSTRAINT fk_sp_shop FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_sku_family FOREIGN KEY (sku_family_id) REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_parent FOREIGN KEY (parent_id) REFERENCES sales_parents(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_portfolio FOREIGN KEY (portfolio_id) REFERENCES amazon_ad_items(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: sessions
-- ----------------------------
CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(128) PRIMARY KEY,
                employee_id INT UNSIGNED NOT NULL,
                expires_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_emp (employee_id),
                CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: shops
-- ----------------------------
CREATE TABLE IF NOT EXISTS shops (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_name VARCHAR(128) NOT NULL,
            platform_type_id INT UNSIGNED NOT NULL,
            brand_id INT UNSIGNED NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_shop (shop_name, platform_type_id, brand_id),
            INDEX idx_shop_platform (platform_type_id),
            INDEX idx_shop_brand (brand_id),
            CONSTRAINT fk_shop_platform_type FOREIGN KEY (platform_type_id)
                REFERENCES platform_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_shop_brand FOREIGN KEY (brand_id)
                REFERENCES brands(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: todo_assignments
-- ----------------------------
CREATE TABLE IF NOT EXISTS todo_assignments (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                todo_id INT UNSIGNED NOT NULL,
                assignee_id INT UNSIGNED NOT NULL,
                assignment_status VARCHAR(16) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uk_todo_assignee (todo_id, assignee_id),
                CONSTRAINT fk_ta_todo FOREIGN KEY (todo_id)
                    REFERENCES todos(id) ON DELETE CASCADE,
                CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id)
                    REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: todos
-- ----------------------------
CREATE TABLE IF NOT EXISTS todos (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                detail TEXT NULL,
                start_date DATE NOT NULL,
                due_date DATE NOT NULL,
                reminder_interval_days INT UNSIGNED NOT NULL DEFAULT 1,
                last_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                next_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                is_recurring TINYINT UNSIGNED NOT NULL DEFAULT 0,
                status VARCHAR(16) NOT NULL DEFAULT 'open',
                priority TINYINT UNSIGNED NOT NULL DEFAULT 2,
                created_by INT UNSIGNED NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_due_date (due_date),
                INDEX idx_status (status),
                INDEX idx_created_by (created_by),
                CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by)
                    REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table: users
-- ----------------------------
CREATE TABLE IF NOT EXISTS users (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(128) NULL,
                phone VARCHAR(64) NULL,
                birthday DATE NULL,
                is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
                can_grant_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
                page_permissions LONGTEXT NULL,
                is_approved TINYINT(1) NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_birthday (birthday),
                INDEX idx_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


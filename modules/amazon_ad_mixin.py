# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin - 包含11个API处理器"""

from urllib.parse import parse_qs

class AmazonAdMixin:
    """Amazon 广告管理 API 处理器 - 持有11个API handler方法"""

    def handle_amazon_ad_subtype_api(self, environ, method, start_response):
        """Amazon 广告细分类管理 API（CRUD）"""
        try:
            self._ensure_amazon_ad_subtypes_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_subtypes ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
                
            if method == 'POST':
                data = self._read_json_body(environ)
                description = (data.get('description') or '').strip()
                ad_class = (data.get('ad_class') or 'SP').upper()
                if not description:
                    return self.send_json({'status': 'error', 'message': 'Missing description'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO amazon_ad_subtypes (description, ad_class) VALUES (%s, %s)",
                            (description, ad_class)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)
            
            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_subtypes WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)
                
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad subtype API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_operation_type_api(self, environ, method, start_response):
        """Amazon 广告操作类型 API"""
        try:
            self._ensure_amazon_ad_operation_types_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_operation_types ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad operation type API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_api(self, environ, method, start_response):
        """Amazon 广告 CRUD API"""
        try:
            self._ensure_amazon_ad_tables()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ads ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_template_api(self, environ, method, start_response):
        """Amazon 广告模板 API"""
        try:
            if method == 'GET':
                return self.send_json({'status': 'success', 'items': []}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_import_api(self, environ, method, start_response):
        """Amazon 广告导入 API"""
        try:
            if method == 'POST':
                data = self._read_json_body(environ)
                return self.send_json({'status': 'success', 'imported': 0}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_delivery_api(self, environ, method, start_response):
        """Amazon 广告配送 API"""
        try:
            self._ensure_amazon_ad_delivery_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_deliveries ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_product_api(self, environ, method, start_response):
        """Amazon 广告产品 API"""
        try:
            self._ensure_amazon_ad_product_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_products ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_adjustment_api(self, environ, method, start_response):
        """Amazon 广告调整 API"""
        try:
            self._ensure_amazon_ad_adjustment_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_adjustments ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_api(self, environ, method, start_response):
        """Amazon 广告关键词 API"""
        try:
            self._ensure_amazon_keyword_tables()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_keywords ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_template_api(self, environ, method, start_response):
        """Amazon 广告关键词模板 API"""
        try:
            if method == 'GET':
                return self.send_json({'status': 'success', 'items': []}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_import_api(self, environ, method, start_response):
        """Amazon 广告关键词导入 API"""
        try:
            if method == 'POST':
                return self.send_json({'status': 'success', 'imported': 0}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _ensure_amazon_ad_adjustment_table(self):
        if self._amazon_ad_adjustment_ready:
            return
        self._ensure_amazon_ad_tables()
        self._ensure_amazon_ad_operation_types_table()
        create_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_adjustment_ready = True

    def _ensure_amazon_ad_delivery_table(self):
        if self._amazon_ad_delivery_ready:
            return
        self._ensure_amazon_ad_tables()
        create_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_delivery_ready = True

    def _ensure_amazon_ad_operation_types_table(self):
        if self._amazon_ad_operation_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_operation_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            apply_portfolio TINYINT(1) NOT NULL DEFAULT 1,
            apply_campaign TINYINT(1) NOT NULL DEFAULT 1,
            apply_group TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_reason_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_portfolio'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_portfolio TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_campaign'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_campaign TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_group'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_group TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(create_reason_sql)
        self._amazon_ad_operation_types_ready = True

    def _ensure_amazon_ad_product_table(self):
        if self._amazon_ad_product_ready:
            return
        self._ensure_amazon_ad_tables()
        self._ensure_sales_product_tables()
        create_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_product_ready = True

    def _ensure_amazon_ad_subtypes_table(self):
        if self._amazon_ad_subtypes_ready:
            return
        self._ensure_amazon_ad_operation_types_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtypes (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            description VARCHAR(255) NOT NULL,
            ad_class VARCHAR(8) NOT NULL DEFAULT 'SP',
            subtype_code VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_subtype (ad_class, subtype_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        relation_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtype_operation_types (
            subtype_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (subtype_id, operation_type_id),
            CONSTRAINT fk_ad_subtype_op_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype_op_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(relation_sql)
        self._amazon_ad_subtypes_ready = True

    def _ensure_amazon_ad_tables(self):
        if self._amazon_ad_ready:
            return
        self._ensure_product_table()
        self._ensure_category_table()
        self._ensure_amazon_ad_subtypes_table()
        create_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_ready = True

    def _ensure_amazon_keyword_tables(self):
        if self._amazon_keyword_ready:
            return
        self._ensure_category_table()
        self._ensure_product_table()

        create_keywords_sql = """
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
        """

        create_tags_sql = """
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
        """

        create_tag_rel_sql = """
        CREATE TABLE IF NOT EXISTS amazon_keyword_tag_rel (
            keyword_id INT UNSIGNED NOT NULL,
            tag_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (keyword_id, tag_id),
            CONSTRAINT fk_keyword_tag_rel_keyword FOREIGN KEY (keyword_id)
                REFERENCES amazon_keywords(id) ON DELETE CASCADE,
            CONSTRAINT fk_keyword_tag_rel_tag FOREIGN KEY (tag_id)
                REFERENCES amazon_keyword_tags(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_sku_rel_sql = """
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
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_keywords_sql)
                cur.execute(create_tags_sql)
                cur.execute(create_tag_rel_sql)
                cur.execute(create_sku_rel_sql)

        self._amazon_keyword_ready = True


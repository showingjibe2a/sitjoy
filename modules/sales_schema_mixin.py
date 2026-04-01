class SalesSchemaMixin:
    def _ensure_sales_parent_tables(self):
        marker_key = 'sales_parent_v1'
        required_tables = ['sales_parents']
        if self._sales_parent_ready:
            return
        if self.__class__._schema_ready_cache.get('sales_parent'):
            self._sales_parent_ready = True
            return
        if self._is_schema_marker_ready(marker_key):
            self._sales_parent_ready = True
            self.__class__._schema_ready_cache['sales_parent'] = True
            return
        try:
            if self._has_required_tables(required_tables):
                self._sales_parent_ready = True
                self.__class__._schema_ready_cache['sales_parent'] = True
                self._set_schema_marker_ready(marker_key)
                return
        except Exception:
            pass

        with self._schema_ensure_lock:
            if self._sales_parent_ready:
                return
            self._ensure_shops_table()
            create_sales_parents = """
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
            """
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_sales_parents)
                    migration_columns = [
                        ("is_enabled", "ALTER TABLE sales_parents ADD COLUMN is_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER parent_code"),
                        ("shop_id", "ALTER TABLE sales_parents ADD COLUMN shop_id INT UNSIGNED NULL AFTER is_enabled"),
                        ("sku_marker", "ALTER TABLE sales_parents ADD COLUMN sku_marker VARCHAR(128) NULL AFTER parent_code"),
                        ("sales_title", "ALTER TABLE sales_parents ADD COLUMN sales_title VARCHAR(200) NULL AFTER estimated_acoas"),
                        ("sales_intro", "ALTER TABLE sales_parents ADD COLUMN sales_intro VARCHAR(500) NULL AFTER sales_title"),
                        ("sales_bullet_1", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_1 VARCHAR(500) NULL AFTER sales_intro"),
                        ("sales_bullet_2", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_2 VARCHAR(500) NULL AFTER sales_bullet_1"),
                        ("sales_bullet_3", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_3 VARCHAR(500) NULL AFTER sales_bullet_2"),
                        ("sales_bullet_4", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_4 VARCHAR(500) NULL AFTER sales_bullet_3"),
                        ("sales_bullet_5", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_5 VARCHAR(500) NULL AFTER sales_bullet_4")
                    ]
                    cur.execute(
                        """
                        SELECT COLUMN_NAME
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_parents'
                        """
                    )
                    existing_columns = {str((row or {}).get('COLUMN_NAME') or '').strip() for row in (cur.fetchall() or [])}
                    for col_name, alter_sql in migration_columns:
                        if col_name in existing_columns:
                            continue
                        try:
                            cur.execute(alter_sql)
                        except Exception:
                            pass
                    try:
                        cur.execute("ALTER TABLE sales_parents ADD INDEX idx_parent_shop (shop_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE sales_parents
                            ADD CONSTRAINT fk_sales_parents_shop
                            FOREIGN KEY (shop_id) REFERENCES shops(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass
                self._sales_parent_ready = True
                self.__class__._schema_ready_cache['sales_parent'] = True
                self._set_schema_marker_ready(marker_key)

    def _ensure_sales_product_tables(self):
        marker_key = 'sales_product_v2'
        required_tables = ['sales_products', 'sales_product_order_links']
        if self._sales_product_ready:
            return
        if self.__class__._schema_ready_cache.get('sales_product'):
            self._sales_product_ready = True
            return
        if self._is_schema_marker_ready(marker_key):
            self._sales_product_ready = True
            self.__class__._schema_ready_cache['sales_product'] = True
            return
        try:
            if self._has_required_tables(required_tables):
                self._sales_product_ready = True
                self.__class__._schema_ready_cache['sales_product'] = True
                self._set_schema_marker_ready(marker_key)
                return
        except Exception:
            pass
        with self._schema_ensure_lock:
            if self._sales_product_ready:
                return
        self._ensure_shops_table()
        self._ensure_sales_parent_tables()
        self._ensure_amazon_ad_tables()
        self._ensure_order_product_tables()

        create_sales_products = """
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
        """

        create_sales_order_links = """
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
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sales_products)
                cur.execute(create_sales_order_links)

                try:
                    cur.execute("""
                        SELECT COLUMN_NAME FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                        AND TABLE_NAME='sales_products'
                        AND COLUMN_NAME='portfolio_id'
                    """)
                    if cur.fetchone():
                        cur.execute("""
                            SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND CONSTRAINT_NAME != 'PRIMARY'
                        """)
                        fk_row = cur.fetchone()
                        if fk_row:
                            fk_name = fk_row['CONSTRAINT_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP FOREIGN KEY {fk_name}")
                        cur.execute("""
                            SELECT INDEX_NAME FROM information_schema.STATISTICS
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND INDEX_NAME != 'PRIMARY'
                        """)
                        idx_row = cur.fetchone()
                        if idx_row:
                            idx_name = idx_row['INDEX_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP INDEX {idx_name}")
                        cur.execute("ALTER TABLE sales_products DROP COLUMN portfolio_id")
                except Exception:
                    pass

                migration_columns = [
                    ("product_status", "ALTER TABLE sales_products ADD COLUMN product_status VARCHAR(16) NOT NULL DEFAULT 'enabled' AFTER platform_sku"),
                    ("sku_family_id", "ALTER TABLE sales_products ADD COLUMN sku_family_id INT UNSIGNED NULL AFTER platform_sku"),
                    ("parent_id", "ALTER TABLE sales_products ADD COLUMN parent_id INT UNSIGNED NULL AFTER platform_sku"),
                    ("child_code", "ALTER TABLE sales_products ADD COLUMN child_code VARCHAR(64) NULL AFTER parent_id"),
                    ("dachene_yuncang_no", "ALTER TABLE sales_products ADD COLUMN dachene_yuncang_no VARCHAR(128) NULL AFTER child_code"),
                    ("sales_title", "ALTER TABLE sales_products ADD COLUMN sales_title VARCHAR(200) NULL AFTER spec_name"),
                    ("sale_price_usd", "ALTER TABLE sales_products ADD COLUMN sale_price_usd DECIMAL(10,2) NULL AFTER spec_name"),
                    ("warehouse_cost_usd", "ALTER TABLE sales_products ADD COLUMN warehouse_cost_usd DECIMAL(10,2) NULL AFTER sale_price_usd"),
                    ("last_mile_cost_usd", "ALTER TABLE sales_products ADD COLUMN last_mile_cost_usd DECIMAL(10,2) NULL AFTER warehouse_cost_usd"),
                    ("package_length_in", "ALTER TABLE sales_products ADD COLUMN package_length_in DECIMAL(10,2) NULL AFTER last_mile_cost_usd"),
                    ("package_width_in", "ALTER TABLE sales_products ADD COLUMN package_width_in DECIMAL(10,2) NULL AFTER package_length_in"),
                    ("package_height_in", "ALTER TABLE sales_products ADD COLUMN package_height_in DECIMAL(10,2) NULL AFTER package_width_in"),
                    ("net_weight_lbs", "ALTER TABLE sales_products ADD COLUMN net_weight_lbs DECIMAL(10,2) NULL AFTER package_height_in"),
                    ("gross_weight_lbs", "ALTER TABLE sales_products ADD COLUMN gross_weight_lbs DECIMAL(10,2) NULL AFTER net_weight_lbs")
                ]
                for col_name, alter_sql in migration_columns:
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA=DATABASE()
                              AND TABLE_NAME='sales_products'
                              AND COLUMN_NAME=%s
                            """,
                            (col_name,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) == 0:
                            cur.execute(alter_sql)
                    except Exception:
                        pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.STATISTICS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND INDEX_NAME='idx_sp_sku_family'
                        """
                    )
                    idx_row = cur.fetchone()
                    if not idx_row or idx_row.get('cnt', 0) == 0:
                        cur.execute("ALTER TABLE sales_products ADD INDEX idx_sp_sku_family (sku_family_id)")
                except Exception:
                    pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.KEY_COLUMN_USAGE
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND CONSTRAINT_NAME='fk_sp_sku_family'
                        """
                    )
                    fk_row = cur.fetchone()
                    if not fk_row or fk_row.get('cnt', 0) == 0:
                        cur.execute(
                            """
                            ALTER TABLE sales_products
                            ADD CONSTRAINT fk_sp_sku_family
                            FOREIGN KEY (sku_family_id) REFERENCES product_families(id)
                            ON DELETE SET NULL
                            """
                        )
                except Exception:
                    pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND COLUMN_NAME='child_asin'
                        """
                    )
                    row = cur.fetchone()
                    if row and row.get('cnt', 0) > 0:
                        cur.execute("UPDATE sales_products SET child_code = child_asin WHERE child_code IS NULL AND child_asin IS NOT NULL")
                        cur.execute("ALTER TABLE sales_products DROP COLUMN child_asin")
                except Exception:
                    pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND COLUMN_NAME='parent_asin'
                        """
                    )
                    row = cur.fetchone()
                    if row and row.get('cnt', 0) > 0:
                        cur.execute(
                            """
                            INSERT IGNORE INTO sales_parents (parent_code)
                            SELECT DISTINCT parent_asin FROM sales_products
                            WHERE parent_asin IS NOT NULL AND parent_asin <> ''
                            """
                        )
                        cur.execute(
                            """
                            UPDATE sales_products sp
                            JOIN sales_parents p ON p.parent_code = sp.parent_asin
                            SET sp.parent_id = p.id
                            WHERE sp.parent_id IS NULL
                            """
                        )
                        cur.execute("ALTER TABLE sales_products DROP COLUMN parent_asin")
                except Exception:
                    pass

                for old_col in ['assembled_length_in', 'assembled_width_in', 'assembled_height_in']:
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA=DATABASE()
                              AND TABLE_NAME='sales_products'
                              AND COLUMN_NAME=%s
                            """,
                            (old_col,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) > 0:
                            cur.execute(f"ALTER TABLE sales_products DROP COLUMN {old_col}")
                    except Exception:
                        pass

                try:
                    cur.execute("ALTER TABLE sales_products ADD INDEX idx_sp_parent (parent_id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_products MODIFY COLUMN shop_id INT UNSIGNED NULL")
                except Exception:
                    pass
                try:
                    cur.execute(
                        """
                        ALTER TABLE sales_products
                        ADD CONSTRAINT fk_sp_parent FOREIGN KEY (parent_id)
                        REFERENCES sales_parents(id) ON DELETE SET NULL
                        """
                    )
                except Exception:
                    pass
        self._sales_product_ready = True
        self.__class__._schema_ready_cache['sales_product'] = True
        self._set_schema_marker_ready(marker_key)

    def _ensure_sales_order_registration_tables(self):
        perf_ctx = self._perf_begin('ensure_sales_order_registration_tables_internal')
        marker_key = 'sales_order_registration_v1'
        required_tables = [
            'sales_order_registrations',
            'sales_order_registration_platform_items',
            'sales_order_registration_shipment_items',
            'sales_order_registration_logistics_items',
        ]
        if self._sales_order_registration_ready:
            return
        if self.__class__._schema_ready_cache.get('sales_order_registration'):
            self._sales_order_registration_ready = True
            return
        try:
            if self._has_required_tables(required_tables):
                self._sales_order_registration_ready = True
                self.__class__._schema_ready_cache['sales_order_registration'] = True
                self._set_schema_marker_ready(marker_key)
                return
        except Exception:
            pass
        if self._is_schema_marker_ready(marker_key):
            try:
                if self._has_required_tables(required_tables):
                    self._sales_order_registration_ready = True
                    self.__class__._schema_ready_cache['sales_order_registration'] = True
                    self._set_schema_marker_ready(marker_key)
                    return
            except Exception:
                pass
        with self._schema_ensure_lock:
            if self._sales_order_registration_ready:
                return
        self._perf_mark(perf_ctx, 'precheck_done')
        self._ensure_sales_product_tables()
        self._ensure_order_product_tables()
        self._ensure_shops_table()
        self._perf_mark(perf_ctx, 'dependent_ensures_done')

        create_orders = """
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
        """

        create_platform_items = """
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
        """

        create_shipment_items = """
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
        """

        create_logistics_items = """
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
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_orders)
                cur.execute(create_platform_items)
                cur.execute(create_shipment_items)
                cur.execute(create_logistics_items)
                self._perf_mark(perf_ctx, 'create_tables_done')
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_shop_order (shop_id, order_no)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_customer_name (customer_name)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_phone (phone)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_logistics_items ADD INDEX idx_sorli_carrier_tracking (shipping_carrier, tracking_no(128))")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_platform_items ADD INDEX idx_sorpi_registration_id_id (registration_id, id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_shipment_items ADD INDEX idx_sorsi_registration_id_id (registration_id, id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_logistics_items ADD INDEX idx_sorli_registration_sort_id (registration_id, sort_order, id)")
                except Exception:
                    pass
                for old_col in ('is_cancelled', 'shipping_carrier', 'tracking_no'):
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'sales_order_registrations'
                              AND COLUMN_NAME = %s
                            """,
                            (old_col,)
                        )
                        row = cur.fetchone() or {}
                        if int(row.get('cnt') or 0) > 0:
                            cur.execute(f"ALTER TABLE sales_order_registrations DROP COLUMN {old_col}")
                    except Exception:
                        pass
            self._sales_order_registration_ready = True
            self.__class__._schema_ready_cache['sales_order_registration'] = True
            self._set_schema_marker_ready(marker_key)
            self._perf_mark(perf_ctx, 'ensure_complete')
            self._perf_end(perf_ctx, force=True)

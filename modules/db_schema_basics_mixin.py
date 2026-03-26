class DbSchemaBasicsMixin:
    def _ensure_product_table(self):
        if self._db_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS product_families (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku_family VARCHAR(64) NOT NULL UNIQUE,
            category VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_sql)
            self._db_ready = True
        except Exception as e:
            self._db_ready = False
            raise e

    def _ensure_category_table(self):
        create_sql = """
        CREATE TABLE IF NOT EXISTS product_categories (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_cn VARCHAR(64) NOT NULL,
            category_en VARCHAR(64) NOT NULL,
            category_en_name VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_category_cn (category_cn),
            UNIQUE KEY uniq_category_en (category_en)
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
                      AND TABLE_NAME = 'product_categories'
                      AND COLUMN_NAME = 'category_en_name'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE product_categories ADD COLUMN category_en_name VARCHAR(128) NOT NULL DEFAULT ''")

    def _ensure_fabric_table(self):
        self._ensure_materials_table()
        self._ensure_product_table()
        create_sql = """
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
        """
        create_images_sql = """
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
        """
        create_fabric_sku_relation = """
        CREATE TABLE IF NOT EXISTS fabric_product_families (
            fabric_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (fabric_id, sku_family_id),
            CONSTRAINT fk_fpf_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE CASCADE,
            CONSTRAINT fk_fpf_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(create_images_sql)
                cur.execute(create_fabric_sku_relation)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_materials'
                      AND COLUMN_NAME = 'material_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE fabric_materials ADD COLUMN material_id INT UNSIGNED NULL")
                    try:
                        cur.execute("ALTER TABLE fabric_materials ADD INDEX idx_fabric_material (material_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE fabric_materials
                            ADD CONSTRAINT fk_fabric_material
                            FOREIGN KEY (material_id) REFERENCES materials(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_materials'
                      AND COLUMN_NAME = 'representative_color'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE fabric_materials ADD COLUMN representative_color VARCHAR(7) NULL AFTER fabric_name_en")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_materials'
                      AND COLUMN_NAME = 'image_name'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    cur.execute(
                        """
                        INSERT INTO fabric_images (fabric_id, image_name, sort_order)
                        SELECT fm.id, fm.image_name, 0
                        FROM fabric_materials fm
                        LEFT JOIN fabric_images fi
                            ON fi.fabric_id = fm.id AND fi.image_name = fm.image_name
                        WHERE fm.image_name IS NOT NULL AND fm.image_name <> ''
                          AND fi.id IS NULL
                        """
                    )
                    try:
                        cur.execute("ALTER TABLE fabric_materials DROP COLUMN image_name")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_images'
                      AND COLUMN_NAME = 'remark'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute(
                        """
                        ALTER TABLE fabric_images
                        ADD COLUMN remark VARCHAR(50) NULL DEFAULT NULL COMMENT '备注类型：平面原图/褶皱原图/卖点图'
                        AFTER sort_order
                        """
                    )
                try:
                    cur.execute("SHOW COLUMNS FROM fabric_images")
                    image_cols = {str((x or {}).get('Field') or '') for x in (cur.fetchall() or [])}
                    if 'is_primary' in image_cols:
                        cur.execute("ALTER TABLE fabric_images DROP COLUMN is_primary")
                except Exception:
                    pass

    def _ensure_material_types_table(self):
        if self._material_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS material_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._material_types_ready = True

    def _ensure_materials_table(self):
        if self._materials_ready:
            return
        self._ensure_material_types_table()
        type_map = {
            'fabric': '面料',
            'filling': '填充',
            'frame': '框架',
            'electronics': '电子元器件'
        }
        create_materials = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_materials)
                cur.execute("SELECT COUNT(*) AS cnt FROM material_types")
                type_count = cur.fetchone()
                if type_count and type_count.get('cnt', 0) == 0:
                    for name in type_map.values():
                        cur.execute("INSERT IGNORE INTO material_types (name) VALUES (%s)", (name,))
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'material_type_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN material_type_id INT UNSIGNED NULL")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'parent_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN parent_id INT UNSIGNED NULL")
                    try:
                        cur.execute("ALTER TABLE materials ADD INDEX idx_material_parent (parent_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE materials
                            ADD CONSTRAINT fk_material_parent
                            FOREIGN KEY (parent_id) REFERENCES materials(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'material_type'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        for code, name in type_map.items():
                            cur.execute(
                                """
                                UPDATE materials m
                                JOIN material_types mt ON mt.name = %s
                                SET m.material_type_id = mt.id
                                WHERE m.material_type_id IS NULL AND m.material_type = %s
                                """,
                                (name, code)
                            )
                    except Exception:
                        pass
                    cur.execute("SELECT COUNT(*) AS cnt FROM materials WHERE material_type_id IS NULL")
                    missing = cur.fetchone()
                    if missing and missing.get('cnt', 0) == 0:
                        try:
                            cur.execute("ALTER TABLE materials MODIFY material_type_id INT UNSIGNED NOT NULL")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE materials ADD UNIQUE KEY uniq_material (material_type_id, name)")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE materials ADD INDEX idx_material_type_id (material_type_id)")
                        except Exception:
                            pass
                        try:
                            cur.execute(
                                """
                                ALTER TABLE materials
                                ADD CONSTRAINT fk_material_type
                                FOREIGN KEY (material_type_id) REFERENCES material_types(id)
                                ON DELETE RESTRICT
                                """
                            )
                        except Exception:
                            pass
        self._materials_ready = True

    def _ensure_platform_types_table(self):
        if self._platform_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS platform_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._platform_types_ready = True

    def _ensure_brands_table(self):
        if self._brands_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS brands (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._brands_ready = True

    def _ensure_shops_table(self):
        if self._shops_ready:
            return
        self._ensure_platform_types_table()
        self._ensure_brands_table()
        create_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._shops_ready = True

    def _ensure_order_product_tables(self):
        if self._order_product_ready:
            return
        self._ensure_product_table()
        self._ensure_fabric_table()
        self._ensure_category_table()
        self._ensure_certification_table()
        self._ensure_materials_table()

        create_order_products = """
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
        """

        create_order_product_materials = """
        CREATE TABLE IF NOT EXISTS order_product_materials (
            order_product_id INT UNSIGNED NOT NULL,
            material_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, material_id),
            CONSTRAINT fk_opm_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opm_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_features = """
        CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_feature_categories = """
        CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_features = """
        CREATE TABLE IF NOT EXISTS order_product_features (
            order_product_id INT UNSIGNED NOT NULL,
            feature_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, feature_id),
            CONSTRAINT fk_opf_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opf_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_certifications = """
        CREATE TABLE IF NOT EXISTS order_product_certifications (
            order_product_id INT UNSIGNED NOT NULL,
            certification_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, certification_id),
            CONSTRAINT fk_opc_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opc_certification FOREIGN KEY (certification_id)
                REFERENCES certifications(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_shipping_plans = """
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
        """

        create_order_product_shipping_plan_items = """
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
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_order_products)
                cur.execute(create_order_product_materials)
                cur.execute(create_features)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'features'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE features ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(create_feature_categories)
                cur.execute(create_order_product_features)
                cur.execute(create_order_product_certifications)
                cur.execute(create_order_product_shipping_plans)
                cur.execute(create_order_product_shipping_plan_items)
                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'order_product_shipping_plans'
                          AND COLUMN_NAME = 'is_default'
                        """
                    )
                    row = cur.fetchone() or {}
                    if int(row.get('cnt') or 0) > 0:
                        cur.execute("ALTER TABLE order_product_shipping_plans DROP COLUMN is_default")
                except Exception:
                    pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'dachene_yuncang_no'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN dachene_yuncang_no")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'spec_qty'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN spec_qty")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'listing_image_b64'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN listing_image_b64")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_iteration'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_iteration TINYINT(1) NOT NULL DEFAULT 0")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_dachene_product'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_dachene_product TINYINT(1) NOT NULL DEFAULT 0 AFTER is_iteration")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_on_market'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_on_market TINYINT(1) NOT NULL DEFAULT 1 AFTER is_dachene_product")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'contents_desc_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN contents_desc_en VARCHAR(255) NULL AFTER spec_qty_short")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'factory_wip_stock'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN factory_wip_stock INT NOT NULL DEFAULT 0 AFTER last_mile_avg_freight_usd")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'source_order_product_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN source_order_product_id INT UNSIGNED NULL")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE order_products ADD INDEX idx_source_order_product (source_order_product_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE order_products
                            ADD CONSTRAINT fk_order_products_source
                            FOREIGN KEY (source_order_product_id) REFERENCES order_products(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass

        self._order_product_ready = True

    def _ensure_todo_tables(self, lightweight=False):
        if self._todo_ready and (lightweight or self._todo_schema_migrated):
            return

        with self._todo_ensure_lock:
            if self._todo_ready and (lightweight or self._todo_schema_migrated):
                return

            create_users = """
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
            """

            create_todos = """
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
            """

            create_todo_assignments = """
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
            """

            create_sessions = """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(128) PRIMARY KEY,
                employee_id INT UNSIGNED NOT NULL,
                expires_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_emp (employee_id),
                CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_users)
                    cur.execute(create_todos)
                    cur.execute(create_todo_assignments)
                    cur.execute(create_sessions)
                    self._todo_ready = True

                    if lightweight:
                        return

                    for col, ddl in (
                        ('name', "ALTER TABLE users ADD COLUMN name VARCHAR(128) NULL"),
                        ('phone', "ALTER TABLE users ADD COLUMN phone VARCHAR(64) NULL"),
                        ('birthday', "ALTER TABLE users ADD COLUMN birthday DATE NULL"),
                        ('is_admin', "ALTER TABLE users ADD COLUMN is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                        ('can_grant_admin', "ALTER TABLE users ADD COLUMN can_grant_admin TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                        ('page_permissions', "ALTER TABLE users ADD COLUMN page_permissions LONGTEXT NULL"),
                        ('is_approved', "ALTER TABLE users ADD COLUMN is_approved TINYINT(1) NOT NULL DEFAULT 1"),
                    ):
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'users'
                              AND COLUMN_NAME = %s
                            """,
                            (col,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) == 0:
                            cur.execute(ddl)

                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = 'can_manage_todos'
                        """
                    )
                    can_manage_col = cur.fetchone()
                    if can_manage_col and can_manage_col.get('cnt', 0) > 0:
                        try:
                            cur.execute("ALTER TABLE users DROP COLUMN can_manage_todos")
                        except Exception:
                            pass

                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = 'employee_id'
                        """
                    )
                    emp_col = cur.fetchone()
                    if emp_col and emp_col.get('cnt', 0) > 0:
                        cur.execute(
                            """
                            SELECT CONSTRAINT_NAME
                            FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'users'
                              AND COLUMN_NAME = 'employee_id'
                              AND REFERENCED_TABLE_NAME IS NOT NULL
                            """
                        )
                        for fk in cur.fetchall() or []:
                            try:
                                cur.execute(f"ALTER TABLE users DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                            except Exception:
                                pass
                        try:
                            cur.execute("ALTER TABLE users MODIFY COLUMN employee_id INT UNSIGNED NULL")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE users DROP COLUMN employee_id")
                        except Exception:
                            pass

                    for table_name in ('users', 'todos', 'todo_assignments', 'sessions'):
                        cur.execute(
                            """
                            SELECT CONSTRAINT_NAME
                            FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = %s
                              AND REFERENCED_TABLE_NAME = 'employees'
                            """,
                            (table_name,)
                        )
                        for fk in cur.fetchall() or []:
                            try:
                                cur.execute(f"ALTER TABLE {table_name} DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                            except Exception:
                                pass

                    try:
                        cur.execute("DROP TABLE IF EXISTS employees")
                    except Exception:
                        pass

                    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin=1")
                    admin_row = cur.fetchone()
                    if admin_row and admin_row.get('cnt', 0) == 0:
                        cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1")
                        first_user = cur.fetchone()
                        if first_user and first_user.get('id'):
                            cur.execute(
                                "UPDATE users SET is_admin=1, can_grant_admin=1, is_approved=1, page_permissions=%s WHERE id=%s",
                                (self._serialize_page_permissions(self._default_page_permissions()), first_user['id'])
                            )

                    try:
                        cur.execute(
                            "ALTER TABLE todos ADD CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            "ALTER TABLE todo_assignments ADD CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            "ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE todo_assignments ADD INDEX idx_ta_assignee_todo (assignee_id, todo_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE todos ADD INDEX idx_todos_creator_due_priority (created_by, due_date, priority, id)")
                    except Exception:
                        pass

            self._todo_schema_migrated = True

    def _ensure_certification_table(self):
        if getattr(self, '_certification_ready', False):
            return
        with self._schema_ensure_lock:
            if getattr(self, '_certification_ready', False):
                return
            create_sql = """
            CREATE TABLE IF NOT EXISTS certifications (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(128) NOT NULL UNIQUE,
                icon_name VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                          AND TABLE_NAME = 'certifications'
                          AND COLUMN_NAME = 'icon_name'
                        """
                    )
                    row = cur.fetchone() or {}
                    if int(row.get('cnt') or 0) == 0:
                        cur.execute("ALTER TABLE certifications ADD COLUMN icon_name VARCHAR(255) NULL AFTER name")
            self._certification_ready = True
            self.__class__._schema_ready_cache['certification'] = True

    def _ensure_certifications_table(self):
        return self._ensure_certification_table()

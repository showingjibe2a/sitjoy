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

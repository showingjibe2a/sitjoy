class LogisticsSchemaMixin:
    def _ensure_logistics_tables(self):
        if self._logistics_ready:
            return
        with self._schema_ensure_lock:
            if self._logistics_ready:
                return
        self._ensure_order_product_tables()
        create_factory_sql = """
        CREATE TABLE IF NOT EXISTS logistics_factories (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            factory_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_forwarder_sql = """
        CREATE TABLE IF NOT EXISTS logistics_forwarders (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            forwarder_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_supplier_sql = """
        CREATE TABLE IF NOT EXISTS logistics_suppliers (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            supplier_name VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_warehouse_sql = """
        CREATE TABLE IF NOT EXISTS logistics_overseas_warehouses (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            warehouse_name VARCHAR(255) NOT NULL,
            supplier_id INT UNSIGNED NOT NULL,
            warehouse_short_name VARCHAR(128) NOT NULL,
            is_enabled TINYINT(1) NOT NULL DEFAULT 1,
            region VARCHAR(32) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_wh_name (warehouse_name),
            UNIQUE KEY uniq_wh_supplier_short (supplier_id, warehouse_short_name),
            INDEX idx_wh_region (region),
            INDEX idx_wh_enabled (is_enabled),
            CONSTRAINT fk_wh_supplier FOREIGN KEY (supplier_id)
                REFERENCES logistics_suppliers(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_inventory_sql = """
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
        """
        create_transit_sql = """
        CREATE TABLE IF NOT EXISTS logistics_in_transit (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            factory_id INT UNSIGNED NOT NULL,
            factory_ship_date_initial DATE NULL,
            factory_ship_date_previous DATE NULL,
            factory_ship_date_latest DATE NULL,
            forwarder_id INT UNSIGNED NOT NULL,
            logistics_box_no VARCHAR(128) NOT NULL,
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
            port_of_loading VARCHAR(128) NULL,
            port_of_destination VARCHAR(128) NULL,
            destination_warehouse_id INT UNSIGNED NULL,
            inbound_order_no VARCHAR(128) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_transit_box_no (logistics_box_no),
            UNIQUE KEY uniq_transit_customs_no (customs_clearance_no),
            UNIQUE KEY uniq_transit_bl_no (bill_of_lading_no),
            INDEX idx_transit_factory (factory_id),
            INDEX idx_transit_forwarder (forwarder_id),
            INDEX idx_transit_wh (destination_warehouse_id),
            CONSTRAINT fk_transit_factory FOREIGN KEY (factory_id)
                REFERENCES logistics_factories(id) ON DELETE RESTRICT,
            CONSTRAINT fk_transit_forwarder FOREIGN KEY (forwarder_id)
                REFERENCES logistics_forwarders(id) ON DELETE RESTRICT,
            CONSTRAINT fk_transit_wh FOREIGN KEY (destination_warehouse_id)
                REFERENCES logistics_overseas_warehouses(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_transit_items_sql = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_factory_sql)
                cur.execute(create_forwarder_sql)
                cur.execute(create_supplier_sql)
                cur.execute(create_warehouse_sql)
                cur.execute(create_inventory_sql)
                cur.execute(create_transit_sql)
                cur.execute(create_transit_items_sql)
                cur.execute("SHOW COLUMNS FROM logistics_overseas_warehouses")
                warehouse_cols = {str((x or {}).get('Field') or '') for x in (cur.fetchall() or [])}
                if 'is_enabled' not in warehouse_cols:
                    cur.execute("ALTER TABLE logistics_overseas_warehouses ADD COLUMN is_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER warehouse_short_name")
                try:
                    cur.execute("ALTER TABLE logistics_overseas_warehouses ADD INDEX idx_wh_enabled (is_enabled)")
                except Exception:
                    pass
                cur.execute("SHOW COLUMNS FROM logistics_in_transit")
                transit_cols = {str((x or {}).get('Field') or '') for x in (cur.fetchall() or [])}
                if 'customs_clearance_no' not in transit_cols:
                    cur.execute("ALTER TABLE logistics_in_transit ADD COLUMN customs_clearance_no VARCHAR(128) NULL AFTER logistics_box_no")
                if 'qty_verified' not in transit_cols:
                    cur.execute("ALTER TABLE logistics_in_transit ADD COLUMN qty_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER clearance_docs_provided")
                if 'qty_consistent' not in transit_cols:
                    cur.execute("ALTER TABLE logistics_in_transit ADD COLUMN qty_consistent TINYINT(1) NOT NULL DEFAULT 0 AFTER qty_verified")
                if 'expected_listed_date_initial' not in transit_cols:
                    cur.execute("ALTER TABLE logistics_in_transit ADD COLUMN expected_listed_date_initial DATE NULL AFTER expected_warehouse_date")
                if 'expected_listed_date_latest' not in transit_cols:
                    cur.execute("ALTER TABLE logistics_in_transit ADD COLUMN expected_listed_date_latest DATE NULL AFTER expected_listed_date_initial")
                cur.execute("SHOW COLUMNS FROM logistics_in_transit_items")
                transit_item_cols = {str((x or {}).get('Field') or '') for x in (cur.fetchall() or [])}
                if 'listed_qty' not in transit_item_cols:
                    cur.execute("ALTER TABLE logistics_in_transit_items ADD COLUMN listed_qty INT NOT NULL DEFAULT 0 AFTER shipped_qty")
            self._logistics_ready = True
            self.__class__._schema_ready_cache['logistics'] = True

    def _ensure_factory_inventory_tables(self):
        if self._factory_inventory_ready:
            return
        with self._schema_ensure_lock:
            if self._factory_inventory_ready:
                return
        self._ensure_logistics_tables()
        create_factory_stock = """
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
        """
        create_factory_wip = """
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
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_factory_stock)
                cur.execute(create_factory_wip)
                cur.execute("SHOW COLUMNS FROM factory_wip_inventory")
                cols = {str((row.get('Field') or '')).strip().lower() for row in (cur.fetchall() or [])}
                if 'is_completed' not in cols:
                    cur.execute("ALTER TABLE factory_wip_inventory ADD COLUMN is_completed TINYINT(1) NOT NULL DEFAULT 0 AFTER expected_completion_date")
                if 'actual_completion_date' not in cols:
                    cur.execute("ALTER TABLE factory_wip_inventory ADD COLUMN actual_completion_date DATE NULL AFTER is_completed")
        self._factory_inventory_ready = True
        self.__class__._schema_ready_cache['factory_inventory'] = True

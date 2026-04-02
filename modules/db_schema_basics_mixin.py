class DbSchemaBasicsMixin:
    """SQL-only模式下的schema占位方法（不再执行运行时DDL）。"""

    def _ensure_product_table(self):
        self._db_ready = True
        self._set_schema_marker_ready('product_family_v1')

    def _ensure_category_table(self):
        return None

    def _ensure_fabric_table(self):
        return None

    def _ensure_material_types_table(self):
        self._material_types_ready = True
        self._set_schema_marker_ready('material_types_v1')

    def _ensure_materials_table(self):
        self._materials_ready = True
        self._set_schema_marker_ready('materials_v1')

    def _ensure_platform_types_table(self):
        self._platform_types_ready = True
        self._set_schema_marker_ready('platform_types_v1')

    def _ensure_brands_table(self):
        self._brands_ready = True
        self._set_schema_marker_ready('brands_v1')

    def _ensure_shops_table(self):
        self._shops_ready = True
        self._set_schema_marker_ready('shops_v1')

    def _ensure_order_product_tables(self):
        self._order_product_ready = True
        self.__class__._schema_ready_cache['order_product'] = True
        self._set_schema_marker_ready('order_product_v2')

    def _ensure_todo_tables(self, lightweight=False):
        self._todo_ready = True
        if not lightweight:
            self._todo_schema_migrated = True
            self._set_schema_marker_ready('todo_v1')

    def _ensure_certification_table(self):
        self._certification_ready = True
        self.__class__._schema_ready_cache['certification'] = True
        self._set_schema_marker_ready('certification_v1')

    def _ensure_certifications_table(self):
        return self._ensure_certification_table()
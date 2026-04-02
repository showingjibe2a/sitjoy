class SalesSchemaMixin:
    def _ensure_sales_parent_tables(self):
        self._sales_parent_ready = True
        self.__class__._schema_ready_cache['sales_parent'] = True
        self._set_schema_marker_ready('sales_parent_v1')

    def _ensure_sales_product_tables(self):
        self._sales_product_ready = True
        self.__class__._schema_ready_cache['sales_product'] = True
        self._set_schema_marker_ready('sales_product_v2')

    def _ensure_sales_order_registration_tables(self):
        self._sales_order_registration_ready = True
        self.__class__._schema_ready_cache['sales_order_registration'] = True
        self._set_schema_marker_ready('sales_order_registration_v1')

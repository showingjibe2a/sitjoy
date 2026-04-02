class LogisticsSchemaMixin:
    def _ensure_logistics_tables(self):
        self._logistics_ready = True
        self.__class__._schema_ready_cache['logistics'] = True
        self._set_schema_marker_ready('logistics_v1')

    def _ensure_factory_inventory_tables(self):
        self._factory_inventory_ready = True
        self.__class__._schema_ready_cache['factory_inventory'] = True
        self._set_schema_marker_ready('factory_inventory_v1')

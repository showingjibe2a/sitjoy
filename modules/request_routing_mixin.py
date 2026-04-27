# 请求路由分发 Mixin：集中管理 API/页面路由与权限检查。

API_PERMISSION_MAP = {
    '/api/employee': 'home',
    '/api/todo': 'home',
    '/api/calendar': 'home',
    '/api/images': 'gallery',
    '/api/browse': 'gallery',
    '/api/image-preview': 'gallery',
    '/api/rename': 'gallery',
    '/api/move': 'gallery',
    '/api/replace': 'gallery',
    '/api/upload': 'gallery',
    '/api/download-zip': 'gallery',
    '/api/gallery-variant-picker': 'gallery',
    '/api/gallery-apply-image': 'gallery',
    '/api/gallery-image-meta': 'gallery',
    '/api/gallery-image-links': 'gallery',
    '/api/gallery-batch-delete': 'gallery',
    '/api/gallery-dup-check': 'gallery',
    '/api/spec-main-images': 'gallery',
    '/api/image-type': 'image_type_management',
    '/api/sku': 'product_management',
    '/api/category': 'product_management',
    '/api/fabric': 'fabric_management',
    '/api/fabric-images': 'fabric_management',
    '/api/fabric-attach': 'fabric_management',
    '/api/fabric-upload': 'fabric_management',
    '/api/fabric-image-delete': 'fabric_management',
    '/api/feature': 'feature_management',
    '/api/material': 'material_management',
    '/api/material-type': 'material_management',
    '/api/platform-type': 'shop_brand_management',
    '/api/brand': 'shop_brand_management',
    '/api/shop': 'shop_brand_management',
    '/api/amazon-account-health': 'amazon_account_health_management',
    '/api/amazon-account-health-template': 'amazon_account_health_management',
    '/api/amazon-account-health-import': 'amazon_account_health_management',
    '/api/amazon-ad-subtype': 'amazon_ad_subtype_management',
    '/api/amazon-ad-operation-type': 'amazon_ad_subtype_management',
    '/api/amazon-ad': 'amazon_ad_management',
    '/api/amazon-ad-template': 'amazon_ad_management',
    '/api/amazon-ad-import': 'amazon_ad_management',
    '/api/amazon-ad-delivery': 'amazon_ad_delivery_management',
    '/api/amazon-ad-product': 'amazon_ad_product_management',
    '/api/amazon-ad-adjustment': 'amazon_ad_adjustment_management',
    '/api/amazon-ad-keyword': 'amazon_ad_keyword_management',
    '/api/amazon-ad-keyword-template': 'amazon_ad_keyword_management',
    '/api/amazon-ad-keyword-import': 'amazon_ad_keyword_management',
    '/api/certification': 'certification_management',
    '/api/order-product': 'order_product_management',
    '/api/order-product-template': 'order_product_management',
    '/api/order-product-import': 'order_product_management',
    '/api/order-product-carton-calc': 'order_product_management',
    '/api/logistics-factory': 'logistics_factory_management',
    '/api/logistics-forwarder': 'logistics_forwarder_management',
    '/api/logistics-supplier': 'logistics_warehouse_management',
    '/api/logistics-destination-region': 'logistics_warehouse_management',
    '/api/logistics-warehouse': 'logistics_warehouse_management',
    '/api/logistics-warehouse-template': 'logistics_warehouse_management',
    '/api/logistics-warehouse-import': 'logistics_warehouse_management',
    '/api/logistics-warehouse-inventory': 'logistics_warehouse_inventory_management',
    '/api/logistics-warehouse-inventory-template': 'logistics_warehouse_inventory_management',
    '/api/logistics-warehouse-inventory-import': 'logistics_warehouse_inventory_management',
    '/api/logistics-warehouse-dashboard': 'logistics_warehouse_dashboard',
    '/api/factory-stock': 'factory_stock_management',
    '/api/factory-wip': 'factory_wip_management',
    '/api/logistics-in-transit': 'logistics_in_transit_management',
    '/api/logistics-in-transit-template': 'logistics_in_transit_management',
    '/api/logistics-in-transit-import': 'logistics_in_transit_management',
    '/api/logistics-in-transit-doc-upload': 'logistics_in_transit_management',
    '/api/logistics-in-transit-doc-files': 'logistics_in_transit_management',
    '/api/sales-product': 'sales_product_management',
    '/api/sales-product-template': 'sales_product_management',
    '/api/sales-product-import': 'sales_product_management',
    '/api/sales-product-main-images': 'sales_product_management',
    '/api/sales-product-main-images-upload': 'sales_product_management',
    '/api/sales-product-main-images-replace': 'sales_product_management',
    '/api/sales-product-main-images-import-by-path': 'sales_product_management',
    '/api/sales-image-type': 'sales_product_management',
    '/api/sales-product-performance': 'sales_product_performance_management',
    '/api/sales-product-performance-template': 'sales_product_performance_management',
    '/api/sales-product-performance-import': 'sales_product_performance_management',
    '/api/sales-product-performance-dashboard': 'sales_product_performance_management',
    '/api/sales-order-registration': 'sales_order_registration_management',
    '/api/sales-order-registration-template': 'sales_order_registration_management',
    '/api/sales-order-registration-import': 'sales_order_registration_management',
    '/api/parent': 'parent_management',
    '/api/aplus-version': 'aplus_management',
    '/api/aplus-version-assets': 'aplus_management',
    '/api/aplus-version-layout': 'aplus_management',
    '/api/aplus-upload': 'aplus_management',
}

PAGE_TEMPLATE_MAP = {
    '/about': ('templates/about.html', 'about'),
    '/about.html': ('templates/about.html', 'about'),
    '/gallery': ('templates/gallery.html', 'gallery'),
    '/spec-main-image-management': ('templates/spec_main_image_management.html', 'gallery'),
    '/image-type-management': ('templates/image_type_management.html', 'image_type_management'),
    '/product-management': ('templates/product_management.html', 'product_management'),
    '/fabric-management': ('templates/fabric_management.html', 'fabric_management'),
    '/feature-management': ('templates/feature_management.html', 'feature_management'),
    '/material-management': ('templates/material_management.html', 'material_management'),
    '/certification-management': ('templates/certification_management.html', 'certification_management'),
    '/order-product-management': ('templates/order_product_management.html', 'order_product_management'),
    '/logistics-factory-management': ('templates/logistics_factory_management.html', 'logistics_factory_management'),
    '/logistics-forwarder-management': ('templates/logistics_forwarder_management.html', 'logistics_forwarder_management'),
    '/logistics-warehouse-management': ('templates/logistics_warehouse_management.html', 'logistics_warehouse_management'),
    '/logistics-warehouse-inventory-management': ('templates/logistics_warehouse_inventory_management.html', 'logistics_warehouse_inventory_management'),
    '/logistics-warehouse-dashboard': ('templates/logistics_warehouse_dashboard.html', 'logistics_warehouse_dashboard'),
    '/logistics-in-transit-management': ('templates/logistics_in_transit_management.html', 'logistics_in_transit_management'),
    '/logistics-in-transit-doc-files': ('templates/logistics_in_transit_doc_files.html', 'logistics_in_transit_management'),
    '/shop-brand-management': ('templates/shop_brand_management.html', 'shop_brand_management'),
    '/amazon-account-health-management': ('templates/amazon_account_health_management.html', 'amazon_account_health_management'),
    '/sales-product-management': ('templates/sales_product_management.html', 'sales_product_management'),
    '/sales-product-performance-management': ('templates/sales_product_performance_management.html', 'sales_product_performance_management'),
    '/sales-order-registration-management': ('templates/sales_order_registration_management.html', 'sales_order_registration_management'),
    '/parent-management': ('templates/parent_management.html', 'parent_management'),
    '/amazon-ad-management': ('templates/amazon_ad_management.html', 'amazon_ad_management'),
    '/amazon-ad-delivery-management': ('templates/amazon_ad_delivery_management.html', 'amazon_ad_delivery_management'),
    '/amazon-ad-product-management': ('templates/amazon_ad_product_management.html', 'amazon_ad_product_management'),
    '/amazon-ad-adjustment-management': ('templates/amazon_ad_adjustment_management.html', 'amazon_ad_adjustment_management'),
    '/amazon-ad-subtype-management': ('templates/amazon_ad_subtype_management.html', 'amazon_ad_subtype_management'),
    '/amazon-ad-keyword-management': ('templates/amazon_ad_keyword_management.html', 'amazon_ad_keyword_management'),
    '/factory-stock-management': ('templates/factory_stock_management.html', 'factory_stock_management'),
    '/factory-wip-management': ('templates/factory_wip_management.html', 'factory_wip_management'),
    '/aplus-management': ('templates/aplus_management.html', 'aplus_management'),
}

API_ROUTE_MAP = {
    '/api/employee': ('method', 'handle_employee_api'),
    '/api/todo': ('method', 'handle_todo_api'),
    '/api/calendar': ('method', 'handle_calendar_api'),
    '/api/images': ('start', 'handle_images_api'),
    '/api/browse': ('start', 'handle_browse_api'),
    '/api/image-preview': ('start', 'handle_image_preview'),
    '/api/rename': ('start', 'handle_rename_api'),
    '/api/move': ('start', 'handle_move_api'),
    '/api/replace': ('start', 'handle_replace_api'),
    '/api/gallery-variant-picker': ('method', 'handle_gallery_variant_picker_api'),
    '/api/gallery-apply-image': ('method', 'handle_gallery_apply_image_api'),
    '/api/gallery-image-meta': ('method', 'handle_gallery_image_meta_api'),
    '/api/gallery-image-links': ('method', 'handle_gallery_image_links_api'),
    '/api/gallery-batch-delete': ('start', 'handle_gallery_batch_delete_api'),
    '/api/gallery-dup-check': ('start', 'handle_gallery_duplicate_check_api'),
    '/api/spec-main-images': ('method', 'handle_spec_main_images_api'),
    '/api/sku': ('method', 'handle_sku_api'),
    '/api/category': ('method', 'handle_category_api'),
    '/api/fabric': ('method', 'handle_fabric_api'),
    '/api/feature': ('method', 'handle_feature_api'),
    '/api/material': ('method', 'handle_material_api'),
    '/api/material-type': ('method', 'handle_material_type_api'),
    '/api/platform-type': ('method', 'handle_platform_type_api'),
    '/api/brand': ('method', 'handle_brand_api'),
    '/api/shop': ('method', 'handle_shop_api'),
    '/api/amazon-account-health': ('method', 'handle_amazon_account_health_api'),
    '/api/amazon-account-health-template': ('method', 'handle_amazon_account_health_template_api'),
    '/api/amazon-account-health-import': ('method', 'handle_amazon_account_health_import_api'),
    '/api/amazon-ad-subtype': ('method', 'handle_amazon_ad_subtype_api'),
    '/api/amazon-ad-operation-type': ('method', 'handle_amazon_ad_operation_type_api'),
    '/api/amazon-ad': ('method', 'handle_amazon_ad_api'),
    '/api/amazon-ad-template': ('method', 'handle_amazon_ad_template_api'),
    '/api/amazon-ad-import': ('method', 'handle_amazon_ad_import_api'),
    '/api/amazon-ad-delivery': ('method', 'handle_amazon_ad_delivery_api'),
    '/api/amazon-ad-product': ('method', 'handle_amazon_ad_product_api'),
    '/api/amazon-ad-adjustment': ('method', 'handle_amazon_ad_adjustment_api'),
    '/api/amazon-ad-keyword': ('method', 'handle_amazon_ad_keyword_api'),
    '/api/amazon-ad-keyword-template': ('method', 'handle_amazon_ad_keyword_template_api'),
    '/api/amazon-ad-keyword-import': ('method', 'handle_amazon_ad_keyword_import_api'),
    '/api/certification': ('method', 'handle_certification_api'),
    '/api/order-product': ('method', 'handle_order_product_api'),
    '/api/order-product-template': ('method', 'handle_order_product_template_api'),
    '/api/order-product-import': ('method', 'handle_order_product_import_api'),
    '/api/order-product-carton-calc': ('method', 'handle_order_product_carton_calc_api'),
    '/api/logistics-factory': ('method', 'handle_logistics_factory_api'),
    '/api/logistics-forwarder': ('method', 'handle_logistics_forwarder_api'),
    '/api/logistics-supplier': ('method', 'handle_logistics_supplier_api'),
    '/api/logistics-destination-region': ('method', 'handle_logistics_destination_region_api'),
    '/api/logistics-warehouse': ('method', 'handle_logistics_warehouse_api'),
    '/api/logistics-warehouse-template': ('method', 'handle_logistics_warehouse_template_api'),
    '/api/logistics-warehouse-import': ('method', 'handle_logistics_warehouse_import_api'),
    '/api/logistics-warehouse-inventory': ('method', 'handle_logistics_warehouse_inventory_api'),
    '/api/logistics-warehouse-inventory-template': ('method', 'handle_logistics_warehouse_inventory_template_api'),
    '/api/logistics-warehouse-inventory-import': ('method', 'handle_logistics_warehouse_inventory_import_api'),
    '/api/logistics-warehouse-dashboard': ('method', 'handle_logistics_warehouse_dashboard_api'),
    '/api/factory-stock': ('method', 'handle_factory_stock_api'),
    '/api/factory-stock-template': ('method', 'handle_factory_stock_template_api'),
    '/api/factory-stock-import': ('method', 'handle_factory_stock_import_api'),
    '/api/factory-wip': ('method', 'handle_factory_wip_api'),
    '/api/factory-wip-template': ('method', 'handle_factory_wip_template_api'),
    '/api/factory-wip-import': ('method', 'handle_factory_wip_import_api'),
    '/api/logistics-in-transit': ('method', 'handle_logistics_in_transit_api'),
    '/api/logistics-in-transit-template': ('method', 'handle_logistics_in_transit_template_api'),
    '/api/logistics-in-transit-import': ('method', 'handle_logistics_in_transit_import_api'),
    '/api/logistics-in-transit-doc-upload': ('start', 'handle_logistics_in_transit_doc_upload_api'),
    '/api/logistics-in-transit-doc-files': ('method', 'handle_logistics_in_transit_doc_files_api'),
    '/api/sales-product': ('method', 'handle_sales_product_api'),
    '/api/parent': ('method', 'handle_parent_api'),
    '/api/sales-product-template': ('method', 'handle_sales_product_template_api'),
    '/api/sales-product-import': ('method', 'handle_sales_product_import_api'),
    '/api/sales-product-main-images': ('method', 'handle_sales_product_main_images_api'),
    '/api/sales-product-main-images-upload': ('start', 'handle_sales_product_main_images_upload_api'),
    '/api/sales-product-main-images-replace': ('start', 'handle_sales_product_main_images_replace_api'),
    '/api/sales-product-main-images-import-by-path': ('method', 'handle_sales_product_main_images_import_by_path_api'),
    '/api/sales-image-type': ('method', 'handle_sales_image_type_api'),
    '/api/sales-product-performance': ('method', 'handle_sales_product_performance_api'),
    '/api/sales-product-performance-template': ('method', 'handle_sales_product_performance_template_api'),
    '/api/sales-product-performance-import': ('method', 'handle_sales_product_performance_import_api'),
    '/api/sales-product-performance-dashboard': ('method', 'handle_sales_product_performance_dashboard_api'),
    '/api/sales-order-registration': ('method', 'handle_sales_order_registration_api'),
    '/api/sales-order-registration-template': ('method', 'handle_sales_order_registration_template_api'),
    '/api/sales-order-registration-import': ('method', 'handle_sales_order_registration_import_api'),
    '/api/fabric-images': ('start', 'handle_fabric_images_api'),
    '/api/fabric-attach': ('start', 'handle_fabric_attach_api'),
    '/api/fabric-upload': ('start', 'handle_fabric_upload_api'),
    '/api/fabric-image-delete': ('method', 'handle_fabric_image_delete_api'),
    '/api/fabric-image-migrate': ('method', 'handle_fabric_image_migrate_api'),
    '/api/upload': ('start', 'handle_upload_api'),
    '/api/download-zip': ('method', 'handle_download_zip'),
    '/api/image-type': ('method', 'handle_image_type_api'),
    '/api/aplus-version': ('method', 'handle_aplus_version_api'),
    '/api/aplus-version-assets': ('method', 'handle_aplus_version_assets_api'),
    '/api/aplus-version-layout': ('method', 'handle_aplus_version_layout_api'),
    '/api/aplus-upload': ('start', 'handle_aplus_upload_api'),
}


class RequestRoutingMixin:
    """请求路由相关能力：API 权限检查 + 页面分发 + API 分发。"""

    def _dispatch_api_request(self, path, environ, method, start_response):
        """统一 API 路由分发，减少主入口分支数量。"""
        if path.startswith('/api/auth'):
            return self.handle_auth_api(environ, method, start_response)
        if path.startswith('/api/hello'):
            return self.handle_hello_api(environ, path, method, start_response)
        if path == '/status':
            return self.handle_status(start_response)

        route = API_ROUTE_MAP.get(path)
        if not route:
            return None
        mode, handler_name = route
        handler = getattr(self, handler_name, None)
        if handler is None:
            return self.send_json({'status': 'error', 'message': f'Handler not found: {handler_name}', 'path': path}, start_response)
        try:
            if mode == 'start':
                return handler(environ, start_response)
            return handler(environ, method, start_response)
        except Exception as e:
            # API 路由层兜底：避免未捕获异常直接冒泡成 Apache 500 页面
            return self.send_json({'status': 'error', 'message': f'API内部错误: {str(e)}', 'path': path}, start_response)

    def _validate_api_permission(self, path, environ, start_response):
        """统一 API 权限校验：返回错误响应或 None。"""
        if not path.startswith('/api/') or path.startswith('/api/auth'):
            return None
        user_id = self._get_session_user(environ)
        if not user_id:
            return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
        permission_key = API_PERMISSION_MAP.get(path)
        if permission_key and not self._user_has_page_access(user_id, permission_key):
            return self.send_json({'status': 'error', 'message': '无权限访问该模块'}, start_response)
        return None

    def _dispatch_page_request(self, path, environ, start_response):
        """统一页面路由分发：返回页面响应或 None。"""
        if path == '/' or path == '/index.html':
            user_id = self._get_session_user(environ)
            if not user_id:
                start_response('302 Found', [('Location', '/login')])
                return [b'']
            if not self._user_has_page_access(user_id, 'home'):
                return self.send_error(403, '无权限访问首页', start_response)
            return self.serve_file('templates/index.html', 'text/html', start_response)

        if path == '/login' or path == '/login.html':
            return self.serve_file('templates/login.html', 'text/html', start_response)

        if path in PAGE_TEMPLATE_MAP:
            template_path, permission_key = PAGE_TEMPLATE_MAP[path]
            return self._serve_protected_page(environ, start_response, template_path, permission_key)

        return None

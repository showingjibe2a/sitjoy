#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSGI 应用入口：负责组装 mixin 与基础初始化。"""

import os
import sys
import threading

from modules.amazon_account_health_mixin import AmazonAccountHealthMixin
from modules.amazon_ad_mixin import AmazonAdMixin
from modules.app_entry_mixin import AppEntryMixin
from modules.auth_employee_mixin import AuthEmployeeMixin
from modules.core_app_mixin import CoreAppMixin
from modules.db_schema_basics_mixin import DbSchemaBasicsMixin
from modules.encoding_utils_mixin import EncodingUtilsMixin
from modules.excel_tools_mixin import ExcelToolsMixin
from modules.fabric_mgmt_mixin import FabricManagementMixin
from modules.file_management_mixin import (
    FileManagementMixin,
    RESOURCES_PATH,
    RESOURCES_PATH_BYTES,
    _RESOURCES_PARENT_BYTES,
)
from modules.file_utils_mixin import FileUtilsMixin
from modules.image_processing_mixin import ImageProcessingMixin
from modules.logistics_in_transit_mixin import LogisticsInTransitMixin
from modules.logistics_schema_mixin import LogisticsSchemaMixin
from modules.logistics_warehouse_mixin import LogisticsWarehouseMixin
from modules.order_mgmt_mixin import OrderManagementMixin
from modules.page_permission_mixin import PagePermissionMixin
from modules.product_mgmt_mixin import ProductManagementMixin
from modules.request_routing_mixin import API_PERMISSION_MAP, PAGE_TEMPLATE_MAP, RequestRoutingMixin
from modules.sales_management_mixin import SalesManagementMixin
from modules.sales_product_mixin import SalesProductMixin
from modules.sales_schema_mixin import SalesSchemaMixin
from modules.support_domain_mixin import SupportDomainMixin
from modules.utility_mixin import UtilityMixin


if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='surrogatepass')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='surrogatepass')


class WSGIApp(
    AppEntryMixin,
    RequestRoutingMixin,
    PagePermissionMixin,
    CoreAppMixin,
    AuthEmployeeMixin,
    UtilityMixin,
    EncodingUtilsMixin,
    ExcelToolsMixin,
    FileUtilsMixin,
    ImageProcessingMixin,
    FileManagementMixin,
    DbSchemaBasicsMixin,
    LogisticsSchemaMixin,
    LogisticsWarehouseMixin,
    LogisticsInTransitMixin,
    SalesSchemaMixin,
    SupportDomainMixin,
    ProductManagementMixin,
    FabricManagementMixin,
    OrderManagementMixin,
    AmazonAccountHealthMixin,
    AmazonAdMixin,
    SalesProductMixin,
    SalesManagementMixin,
):
    _schema_ready_cache = {
        'certification': False,
        'order_product': False,
        'sales_parent': False,
        'sales_product': False,
        'sales_order_registration': False,
        'logistics': False,
        'factory_inventory': False,
    }

    _DB_SCHEMA_ENSURE_METHODS = [
        '_ensure_product_table',
        '_ensure_category_table',
        '_ensure_fabric_table',
        '_ensure_material_types_table',
        '_ensure_materials_table',
        '_ensure_platform_types_table',
        '_ensure_brands_table',
        '_ensure_shops_table',
        '_ensure_order_product_tables',
        '_ensure_todo_tables',
        '_ensure_certification_table',
        '_ensure_certifications_table',
        '_ensure_sales_parent_tables',
        '_ensure_sales_product_tables',
        '_ensure_sales_order_registration_tables',
        '_ensure_logistics_tables',
        '_ensure_factory_inventory_tables',
        '_ensure_amazon_account_health_table',
        '_ensure_amazon_ad_adjustment_table',
        '_ensure_amazon_ad_delivery_table',
        '_ensure_amazon_ad_operation_types_table',
        '_ensure_amazon_ad_product_table',
        '_ensure_amazon_ad_subtypes_table',
        '_ensure_amazon_ad_tables',
        '_ensure_amazon_keyword_tables',
    ]

    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self._user_session = {}
        self._template_options_cache = {}
        self._schema_ensure_lock = threading.Lock()
        self._todo_ensure_lock = threading.Lock()

        ready_flags = [
            '_db_ready',
            '_material_types_ready',
            '_materials_ready',
            '_platform_types_ready',
            '_brands_ready',
            '_shops_ready',
            '_order_product_ready',
            '_todo_ready',
            '_todo_schema_migrated',
            '_certification_ready',
            '_logistics_ready',
            '_factory_inventory_ready',
            '_sales_parent_ready',
            '_sales_product_ready',
            '_sales_order_registration_ready',
            '_amazon_account_health_ready',
            '_amazon_ad_adjustment_ready',
            '_amazon_ad_delivery_ready',
            '_amazon_ad_operation_types_ready',
            '_amazon_ad_product_ready',
            '_amazon_ad_subtypes_ready',
            '_amazon_ad_ready',
            '_amazon_keyword_ready',
        ]
        for flag_name in ready_flags:
            setattr(self, flag_name, False)

        self._apply_sql_only_runtime_guard()

        self.PAGE_PERMISSION_KEYS = self._build_page_permission_keys()
        self.PAGE_PERMISSION_LABELS = {key: key for key in self.PAGE_PERMISSION_KEYS}

    @staticmethod
    def _build_page_permission_keys():
        ordered = []
        seen = set()

        def add_key(key):
            key_text = (key or '').strip()
            if not key_text or key_text in seen:
                return
            seen.add(key_text)
            ordered.append(key_text)

        add_key('home')
        add_key('about')
        for key in API_PERMISSION_MAP.values():
            add_key(key)
        for _, (_, key) in PAGE_TEMPLATE_MAP.items():
            add_key(key)
        return ordered

    def _noop_schema_ensure(self, *args, **kwargs):
        """
        空操作函数（no-op）。
        
        用来替换所有 _ensure_*() 方法，使其变为无操作。
        在 _apply_sql_only_runtime_guard() 中作为替换目标。
        """
        return None

    def _apply_sql_only_runtime_guard(self):
            def _apply_sql_only_runtime_guard(self):
                """
                应用 SQL_ONLY 模式运行时保护：将所有 _ensure_*() 方法替换为 no-op。
        
                业务流程：
                1. 检查 SITJOY_SQL_ONLY 环境变量（via _is_sql_only_mode()）
                2. 若已启用，遍历 _DB_SCHEMA_ENSURE_METHODS 列表
                3. 将每个方法（如 _ensure_product_table, _ensure_sales_parent_tables）
                   替换为 _noop_schema_ensure
        
                目的：
                - 完全禁用运行时 DDL（建表、改表、补索引、补外键）
                - 即使代码中仍有 _ensure_*() 调用，也会变为无操作
                - 配合 SQL_ONLY 环境变量，构成双重保护机制
        
                调用时机：应用启动时（__init__() 中）
                """
                if not self._is_sql_only_mode():
                    return
                for method_name in self._DB_SCHEMA_ENSURE_METHODS:
                    try:
                        if hasattr(self, method_name):
                            setattr(self, method_name, self._noop_schema_ensure)
                    except Exception:
                        pass
        if not self._is_sql_only_mode():
            return
        for method_name in self._DB_SCHEMA_ENSURE_METHODS:
            try:
                if hasattr(self, method_name):
                    setattr(self, method_name, self._noop_schema_ensure)
            except Exception:
                pass


application = WSGIApp()

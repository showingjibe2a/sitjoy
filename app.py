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


application = WSGIApp()

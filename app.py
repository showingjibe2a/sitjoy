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
from modules.logistics_warehouse_mixin import LogisticsWarehouseMixin
from modules.order_mgmt_mixin import OrderManagementMixin
from modules.page_permission_mixin import PagePermissionMixin
from modules.product_mgmt_mixin import ProductManagementMixin
from modules.request_routing_mixin import API_PERMISSION_MAP, PAGE_TEMPLATE_MAP, RequestRoutingMixin
from modules.sales_management_mixin import SalesManagementMixin
from modules.sales_product_mixin import SalesProductMixin
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
    LogisticsWarehouseMixin,
    LogisticsInTransitMixin,
    SupportDomainMixin,
    ProductManagementMixin,
    FabricManagementMixin,
    OrderManagementMixin,
    AmazonAccountHealthMixin,
    AmazonAdMixin,
    SalesProductMixin,
    SalesManagementMixin,
):
    _schema_ready_cache = {}

    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self._user_session = {}
        self._template_options_cache = {}
        self._schema_ensure_lock = threading.Lock()
        self._todo_ensure_lock = threading.Lock()

        self.PAGE_PERMISSION_KEYS = self._build_page_permission_keys()
        label_map = {
            'home': '首页',
            'about': '关于 - 我的网页',
            'shop_brand_management': '店铺/品牌管理',
            'amazon_account_health_management': 'Amazon账户健康',
            'amazon_ad_management': '广告信息管理',
            'amazon_ad_subtype_management': '广告信息分类管理',
            'amazon_ad_delivery_management': '广告投放管理',
            'amazon_ad_product_management': '广告商品管理',
            'amazon_ad_adjustment_management': '广告调整',
            'amazon_ad_keyword_management': 'Amazon关键词管理',
            'logistics_factory_management': '工厂管理',
            'logistics_forwarder_management': '货代管理',
            'logistics_warehouse_management': '海外仓仓库管理',
            'logistics_warehouse_inventory_management': '海外仓库存管理',
            'logistics_in_transit_management': '在途物流库存管理',
            'logistics_warehouse_dashboard': '仓储看板',
            'factory_stock_management': '工厂在库库存管理',
            'factory_wip_management': '工厂在制库存管理',
            'product_management': '品类/货号管理',
            'fabric_management': '面料管理',
            'feature_management': '卖点管理',
            'material_management': '材料管理',
            'certification_management': '认证管理',
            'order_product_management': '下单产品管理',
            'sales_product_management': '销售产品管理',
            'sales_product_performance_management': '产品表现看板',
            'sales_order_registration_management': '订单登记管理',
            'parent_management': '父体管理',
            'gallery': '图片管理'
        }
        self.PAGE_PERMISSION_LABELS = {
            key: label_map.get(key, key.replace('_', ' '))
            for key in self.PAGE_PERMISSION_KEYS
        }
        self.PAGE_PERMISSION_GROUPS = [
            {'key': 'home', 'title': '首页', 'page_keys': ['home']},
            {'key': 'shop_brand_management', 'title': '店铺管理', 'page_keys': ['shop_brand_management', 'amazon_account_health_management']},
            {'key': 'product_management', 'title': '产品管理', 'page_keys': ['product_management', 'fabric_management', 'feature_management', 'material_management', 'certification_management', 'order_product_management']},
            {'key': 'logistics_factory_management', 'title': '物流仓储管理', 'page_keys': ['logistics_factory_management', 'logistics_forwarder_management', 'logistics_warehouse_management', 'logistics_warehouse_inventory_management', 'logistics_in_transit_management', 'factory_stock_management', 'factory_wip_management', 'logistics_warehouse_dashboard']},
            {'key': 'gallery', 'title': '图片管理', 'page_keys': ['gallery']},
            {'key': 'sales_product_management', 'title': '销售管理', 'page_keys': ['sales_product_management', 'sales_product_performance_management', 'sales_order_registration_management', 'parent_management']},
            {'key': 'amazon_ad_adjustment_management', 'title': 'Amazon广告管理', 'page_keys': ['amazon_ad_adjustment_management', 'amazon_ad_keyword_management', 'amazon_ad_management', 'amazon_ad_subtype_management', 'amazon_ad_delivery_management', 'amazon_ad_product_management']},
            {'key': 'about', 'title': '关于', 'page_keys': ['about']}
        ]

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

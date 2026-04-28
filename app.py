#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSGI 应用入口：负责组装 mixin 与基础初始化。"""

import os
import sys
import threading

# 导入各个功能模块（Mixin）
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
from modules.aplus_mixin import AplusMixin
from modules.sales_management_mixin import SalesManagementMixin
from modules.sales_product_mixin import SalesProductMixin
from modules.support_domain_mixin import SupportDomainMixin
from modules.utility_mixin import UtilityMixin

# 解决标准输出/错误输出的编码问题，确保在控制台打印中文时不报错
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='surrogatepass')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='surrogatepass')

# 定义主应用类：通过“多重继承”将所有功能合并到一个类中
class WSGIApp(
    AppEntryMixin,            # 启动入口逻辑
    RequestRoutingMixin,      # 路由分发逻辑
    PagePermissionMixin,      # 页面权限控制
    CoreAppMixin,             # 核心基础逻辑
    AuthEmployeeMixin,        # 员工权限认证
    UtilityMixin,             # 工具集：通用
    EncodingUtilsMixin,       # 工具集：编码处理
    ExcelToolsMixin,          # 工具集：Excel处理
    FileUtilsMixin,           # 工具集：文件处理
    ImageProcessingMixin,     # 工具集：图片处理
    FileManagementMixin,      # 工具集：资源文件管理
    LogisticsWarehouseMixin,  # 仓库物流
    LogisticsInTransitMixin,  # 在途物流
    SupportDomainMixin,       # 支撑域逻辑
    ProductManagementMixin,   # 产品管理
    FabricManagementMixin,    # 面料管理
    OrderManagementMixin,     # 订单管理
    AmazonAccountHealthMixin, # 亚马逊账户健康
    AmazonAdMixin,            # 亚马逊广告
    SalesProductMixin,        # 销售产品
    AplusMixin,               # A+ 页面
    SalesManagementMixin,     # 销售管理
):
    # 用于缓存数据库 Schema 是否准备就绪，避免重复检查
    _schema_ready_cache = {}

    def __init__(self):
        # 1. 初始化基础环境
        self.base_path = os.path.dirname(os.path.abspath(__file__)) # 获取项目根目录
        self._user_session = {}                                     # 简单的内存会话存储
        self._template_options_cache = {}                           # 模板选项缓存
        self._schema_ensure_lock = threading.Lock()                 # 数据库结构同步锁
        self._todo_ensure_lock = threading.Lock()                   # 待办事项同步锁
        
        # 2. 构建权限键值列表
        self.PAGE_PERMISSION_KEYS = self._build_page_permission_keys()

        # 3. 定义页面 ID 与中文名称的映射关系，用于权限控制和界面显示
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
            'sales_forecast_management': '销量预测',
            'parent_management': '父体管理',
            'gallery': '图片管理',
            'image_type_management': '图片类型管理',
            'aplus_management': 'A+管理',
        }

        # 将上面定义的中文名应用到权限列表里
        self.PAGE_PERMISSION_LABELS = {
            key: label_map.get(key, key.replace('_', ' '))
            for key in self.PAGE_PERMISSION_KEYS
        }

        # 4. 定义菜单栏的分组结构
        self.PAGE_PERMISSION_GROUPS = [
            {'key': 'home', 'title': '首页', 'page_keys': ['home']},
            {'key': 'shop_brand_management', 'title': '店铺管理', 'page_keys': ['shop_brand_management', 'amazon_account_health_management']},
            {'key': 'product_management', 'title': '产品管理', 'page_keys': ['product_management', 'fabric_management', 'feature_management', 'material_management', 'certification_management', 'order_product_management']},
            {'key': 'logistics_factory_management', 'title': '物流仓储管理', 'page_keys': ['logistics_factory_management', 'logistics_forwarder_management', 'logistics_warehouse_management', 'logistics_warehouse_inventory_management', 'logistics_in_transit_management', 'factory_stock_management', 'factory_wip_management', 'logistics_warehouse_dashboard']},
            {'key': 'gallery', 'title': '图片管理', 'page_keys': ['gallery', 'image_type_management', 'aplus_management']},
            {'key': 'sales_product_management', 'title': '销售管理', 'page_keys': ['sales_product_management', 'sales_product_performance_management', 'sales_forecast_management', 'sales_order_registration_management', 'parent_management']},
            {'key': 'amazon_ad_adjustment_management', 'title': 'Amazon广告管理', 'page_keys': ['amazon_ad_adjustment_management', 'amazon_ad_keyword_management', 'amazon_ad_management', 'amazon_ad_subtype_management', 'amazon_ad_delivery_management', 'amazon_ad_product_management']},
            {'key': 'about', 'title': '关于', 'page_keys': ['about']}
        ]

    @staticmethod
    def _build_page_permission_keys():
        """自动扫描并汇总所有需要权限控制的页面 Key"""
        ordered = []
        seen = set()

        def add_key(key):
            key_text = (key or '').strip()
            if not key_text or key_text in seen:
                return
            seen.add(key_text)
            ordered.append(key_text)

        # 强制添加首页和关于页
        add_key('home')
        add_key('about')

        # 从路由映射表和模板映射表中自动提取权限 Key
        for key in API_PERMISSION_MAP.values():
            add_key(key)
        for _, (_, key) in PAGE_TEMPLATE_MAP.items():
            add_key(key)
        return ordered

# 最终实例化的 application 对象供 WSGI 服务器（如 Gunicorn, uWSGI）调用
application = WSGIApp()

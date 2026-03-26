#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSGI 应用 - 用于 Synology Web Station
兼容 Apache + mod_wsgi
"""

import sys
import os

# 强制设置所有I/O为UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

os.environ['PYTHONIOENCODING'] = 'utf-8'

from urllib.parse import urlparse, parse_qs, quote
import json
import ast
import re
from datetime import datetime, timedelta
import calendar
import mimetypes
import base64
import io
from pathlib import Path
import time
import cgi
import tempfile
import zipfile
import xml.etree.ElementTree as ET
import hmac
import hashlib
import secrets
import unicodedata
import threading
try:
    from PIL import Image
    _pillow_import_error = None
except Exception as e:
    Image = None
    _pillow_import_error = str(e)
try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)
try:
    import pymysql
    _pymysql_import_error = None
except Exception as e:
    pymysql = None
    _pymysql_import_error = str(e)

# 导入业务逻辑 mixin 模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
try:
    from auth_employee_mixin import AuthEmployeeMixin
    from core_app_mixin import CoreAppMixin
    from db_schema_basics_mixin import DbSchemaBasicsMixin
    from excel_tools_mixin import ExcelToolsMixin
    from file_management_mixin import FileManagementMixin
    from request_routing_mixin import RequestRoutingMixin
    from logistics_warehouse_mixin import LogisticsWarehouseMixin
    from logistics_in_transit_mixin import LogisticsInTransitMixin
    from sales_product_mixin import SalesProductMixin
    from sales_management_mixin import SalesManagementMixin
    from app_entry_mixin import AppEntryMixin
    from page_permission_mixin import PagePermissionMixin
    from logistics_schema_mixin import LogisticsSchemaMixin
    from sales_schema_mixin import SalesSchemaMixin
    from product_mgmt_mixin import ProductManagementMixin
    from fabric_mgmt_mixin import FabricManagementMixin
    from order_mgmt_mixin import OrderManagementMixin
    from utility_mixin import UtilityMixin
    from amazon_ad_mixin import AmazonAdMixin
    from support_domain_mixin import SupportDomainMixin
    _mixin_import_error = None
except Exception as e:
    _mixin_import_error = str(e)
    # 定义空的 mixin 类以防导入失败
    class AuthEmployeeMixin: pass
    class CoreAppMixin: pass
    class DbSchemaBasicsMixin: pass
    class ExcelToolsMixin: pass
    class FileManagementMixin: pass
    class RequestRoutingMixin: pass
    class LogisticsWarehouseMixin: pass
    class LogisticsInTransitMixin: pass
    class SalesProductMixin: pass
    class SalesManagementMixin: pass
    class AppEntryMixin: pass
    class PagePermissionMixin: pass
    class LogisticsSchemaMixin: pass
    class SalesSchemaMixin: pass
    class ProductManagementMixin: pass
    class FabricManagementMixin: pass
    class OrderManagementMixin: pass
    class UtilityMixin: pass
    class AmazonAdMixin: pass
    class SupportDomainMixin: pass

# 外部文件夹路径
# 使用 Base64 的子目录名，避免手动输入特殊字符出错
_RESOURCES_PARENT = '/volume1/公共文件SITJOY'
_RESOURCES_CHILD_B64 = '44CO5LiK5p626LWE5rqQ44CP'
_RESOURCES_PARENT_BYTES = _RESOURCES_PARENT.encode('utf-8', errors='surrogatepass')
_RESOURCES_CHILD_BYTES = base64.b64decode(_RESOURCES_CHILD_B64)
RESOURCES_PATH_BYTES = os.path.join(_RESOURCES_PARENT_BYTES, _RESOURCES_CHILD_BYTES)
RESOURCES_PATH = os.fsdecode(RESOURCES_PATH_BYTES)

PAGE_PERMISSION_DEFINITIONS = [
    ('home', '首页', '/', 'templates/index.html'),
    ('about', '关于', '/about', 'templates/about.html'),
    ('gallery', '图片管理', '/gallery', 'templates/gallery.html'),
    ('shop_brand_management', '店铺/品牌管理', '/shop-brand-management', 'templates/shop_brand_management.html'),
    ('amazon_account_health_management', 'Amazon账户健康', '/amazon-account-health-management', 'templates/amazon_account_health_management.html'),
    ('product_management', '品类/货号管理', '/product-management', 'templates/product_management.html'),
    ('fabric_management', '面料管理', '/fabric-management', 'templates/fabric_management.html'),
    ('feature_management', '卖点管理', '/feature-management', 'templates/feature_management.html'),
    ('material_management', '材料管理', '/material-management', 'templates/material_management.html'),
    ('certification_management', '认证管理', '/certification-management', 'templates/certification_management.html'),
    ('order_product_management', '下单产品管理', '/order-product-management', 'templates/order_product_management.html'),
    ('logistics_factory_management', '工厂管理', '/logistics-factory-management', 'templates/logistics_factory_management.html'),
    ('logistics_forwarder_management', '货代管理', '/logistics-forwarder-management', 'templates/logistics_forwarder_management.html'),
    ('logistics_warehouse_management', '海外仓仓库管理', '/logistics-warehouse-management', 'templates/logistics_warehouse_management.html'),
    ('logistics_warehouse_inventory_management', '海外仓库存管理', '/logistics-warehouse-inventory-management', 'templates/logistics_warehouse_inventory_management.html'),
    ('logistics_in_transit_management', '在途物流库存管理', '/logistics-in-transit-management', 'templates/logistics_in_transit_management.html'),
    ('logistics_warehouse_dashboard', '仓储看板', '/logistics-warehouse-dashboard', 'templates/logistics_warehouse_dashboard.html'),
    ('sales_product_management', '销售产品管理', '/sales-product-management', 'templates/sales_product_management.html'),
    ('sales_order_registration_management', '订单登记管理', '/sales-order-registration-management', 'templates/sales_order_registration_management.html'),
    ('parent_management', '父体管理', '/parent-management', 'templates/parent_management.html'),
    ('amazon_ad_adjustment_management', '广告调整', '/amazon-ad-adjustment-management', 'templates/amazon_ad_adjustment_management.html'),
    ('amazon_ad_keyword_management', 'Amazon关键词管理', '/amazon-ad-keyword-management', 'templates/amazon_ad_keyword_management.html'),
    ('amazon_ad_management', '广告信息管理', '/amazon-ad-management', 'templates/amazon_ad_management.html'),
    ('amazon_ad_subtype_management', '广告信息分类管理', '/amazon-ad-subtype-management', 'templates/amazon_ad_subtype_management.html'),
    ('amazon_ad_delivery_management', '广告投放管理', '/amazon-ad-delivery-management', 'templates/amazon_ad_delivery_management.html'),
    ('amazon_ad_product_management', '广告商品管理', '/amazon-ad-product-management', 'templates/amazon_ad_product_management.html'),
    ('factory_stock_management', '工厂在库库存管理', '/factory-stock-management', 'templates/factory_stock_management.html'),
    ('factory_wip_management', '工厂在制库存管理', '/factory-wip-management', 'templates/factory_wip_management.html'),
]

PAGE_PERMISSION_KEYS = [item[0] for item in PAGE_PERMISSION_DEFINITIONS]
PAGE_PERMISSION_LABELS = {item[0]: item[1] for item in PAGE_PERMISSION_DEFINITIONS}
PAGE_TEMPLATE_MAP = {
    '/about': ('templates/about.html', 'about'),
    '/about.html': ('templates/about.html', 'about'),
    '/gallery': ('templates/gallery.html', 'gallery'),
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
}
API_PERMISSION_MAP = {
    '/api/employee': 'home',
    '/api/todo': 'home',
    '/api/calendar': 'home',
    '/api/images': 'gallery',
    '/api/browse': 'gallery',
    '/api/image-preview': 'gallery',
    '/api/rename': 'gallery',
    '/api/move': 'gallery',
    '/api/upload': 'gallery',
    '/api/download-zip': 'gallery',
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
    '/api/certification-images': 'certification_management',
    '/api/order-product': 'order_product_management',
    '/api/order-product-template': 'order_product_management',
    '/api/order-product-import': 'order_product_management',
    '/api/order-product-carton-calc': 'order_product_management',
    '/api/logistics-factory': 'logistics_factory_management',
    '/api/logistics-forwarder': 'logistics_forwarder_management',
    '/api/logistics-supplier': 'logistics_warehouse_management',
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
    '/api/sales-order-registration': 'sales_order_registration_management',
    '/api/sales-order-registration-template': 'sales_order_registration_management',
    '/api/sales-order-registration-import': 'sales_order_registration_management',
    '/api/parent': 'parent_management',
}

class WSGIApp(AppEntryMixin, PagePermissionMixin, AuthEmployeeMixin, DbSchemaBasicsMixin, CoreAppMixin, ExcelToolsMixin, FileManagementMixin, RequestRoutingMixin, LogisticsWarehouseMixin, LogisticsInTransitMixin, SalesProductMixin, SalesManagementMixin, ProductManagementMixin, FabricManagementMixin, OrderManagementMixin, UtilityMixin, AmazonAdMixin, SupportDomainMixin):
    """WSGI 应用处理器 - 通过继承各类 mixin 提供综合功能"""
    PAGE_PERMISSION_KEYS = tuple(PAGE_PERMISSION_KEYS)
    _schema_ready_cache = {
        'certification': False,
        'sales_parent': False,
        'sales_order_registration': False,
        'logistics': False,
        'factory_inventory': False,
    }
    
    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self._db_ready = False
        self._order_product_ready = False
        self._material_types_ready = False
        self._materials_ready = False
        self._platform_types_ready = False
        self._brands_ready = False
        self._shops_ready = False
        self._amazon_account_health_ready = False
        self._amazon_ad_ready = False
        self._amazon_ad_delivery_ready = False
        self._amazon_ad_product_ready = False
        self._amazon_ad_adjustment_ready = False
        self._amazon_ad_subtypes_ready = False
        self._amazon_ad_operation_types_ready = False
        self._amazon_keyword_ready = False
        self._sales_parent_ready = bool(self.__class__._schema_ready_cache.get('sales_parent'))
        self._sales_product_ready = False
        self._sales_order_registration_ready = bool(self.__class__._schema_ready_cache.get('sales_order_registration'))
        self._logistics_ready = bool(self.__class__._schema_ready_cache.get('logistics'))
        self._factory_inventory_ready = bool(self.__class__._schema_ready_cache.get('factory_inventory'))
        self._certification_ready = bool(self.__class__._schema_ready_cache.get('certification'))
        self._todo_ready = False
        self._todo_schema_migrated = False
        self._todo_ensure_lock = threading.Lock()
        self._schema_ensure_lock = threading.RLock()
        self._category_ready = False
        self._fabric_ready = False
        self._user_session = {}
        self._template_options_cache = {}

    def _get_session_id(self, environ):
        """从 cookie 获取 session_id"""
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == 'session_id'), None)

    def _get_cookie_value(self, environ, name):
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == name), None)

    def _get_auth_secret(self):
        # Stable secret derived from env or db config, avoids cross-worker mismatch
        env_secret = os.environ.get('SITJOY_AUTH_SECRET')
        if env_secret:
            return env_secret.encode('utf-8', errors='ignore')
        cfg = self._get_db_config() or {}
        seed = f"{cfg.get('host','')}|{cfg.get('user','')}|{cfg.get('password','')}|{cfg.get('database','')}"
        return hashlib.sha256(seed.encode('utf-8', errors='ignore')).digest()

    def _b64url_encode(self, raw):
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    def _b64url_decode(self, text):
        pad = '=' * (-len(text) % 4)
        return base64.urlsafe_b64decode((text + pad).encode('ascii'))

    def _make_stateless_token(self, user_id, ttl_seconds=7 * 24 * 3600):
        exp = int(time.time()) + int(ttl_seconds)
        payload = f"{user_id}|{exp}".encode('utf-8', errors='surrogatepass')
        sig = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
        return self._b64url_encode(payload + b'|' + sig)

    def _verify_stateless_token(self, token):
        if not token:
            return None
        try:
            raw = self._b64url_decode(token)
            parts = raw.split(b'|')
            if len(parts) != 3:
                return None
            user_id_b, exp_b, sig_b = parts
            payload = user_id_b + b'|' + exp_b
            expected = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
            if not hmac.compare_digest(sig_b, expected):
                return None
            exp = int(exp_b.decode('utf-8', errors='ignore') or '0')
            if exp < int(time.time()):
                return None
            return int(user_id_b.decode('utf-8', errors='ignore'))
        except Exception:
            return None

    def _get_session_user(self, environ):
        """从cookie读取登录用户ID"""
        session_id = self._get_session_id(environ)
        token = self._get_cookie_value(environ, 'session_token')
        token_user = self._verify_stateless_token(token)
        if token_user:
            if session_id and session_id not in self._user_session:
                self._user_session[session_id] = token_user
            return token_user
        if not session_id:
            # stateless fallback for environments where DB sessions fail
            if token_user:
                return token_user
        if session_id:
            # 先检查内存缓存
            if session_id in self._user_session:
                return self._user_session[session_id]
            # 回退到数据库查询（支持多进程部署）
            try:
                cfg = self._get_db_config()
                if cfg:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT employee_id FROM sessions WHERE session_id=%s AND (expires_at IS NULL OR expires_at>NOW())",
                                (session_id,)
                            )
                            row = cur.fetchone()
                            if row and row.get('employee_id'):
                                self._user_session[session_id] = row['employee_id']
                                return row['employee_id']
            except Exception as e:
                print(f"Session DB lookup failed: {type(e).__name__}: {e}")
            # session_id 无效时，尝试 stateless token 作为回退
            if token_user:
                return token_user
        return None

    def _set_session_user(self, user_id):
        """创建session并返回session_id"""
        import uuid
        session_id = str(uuid.uuid4())
        # 写入内存缓存
        self._user_session[session_id] = user_id
        # 尝试写入数据库以便在多进程下共享会话
        try:
            cfg = self._get_db_config()
            if cfg:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        # 过期时间设为 7 天
                        cur.execute(
                            "REPLACE INTO sessions (session_id, employee_id, expires_at) VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 7 DAY))",
                            (session_id, user_id)
                        )
        except Exception as e:
            print(f"Session DB write failed: {type(e).__name__}: {e}")
        return session_id

    def _b64_from_fs(self, value):
        """将文件系统路径/名称转为 Base64（保留原始字节）"""
        try:
            raw = self._safe_fsencode(value)
        except Exception:
            raw = str(value).encode('utf-8', errors='surrogatepass')
        return base64.b64encode(raw).decode('ascii')

    def _fs_from_b64(self, value):
        """从 Base64 还原文件系统路径/名称"""
        raw = base64.b64decode(value)
        return os.fsdecode(raw)

    def _join_resources(self, rel_path):
        """拼接资源目录（返回 bytes 路径）"""
        if not rel_path:
            return RESOURCES_PATH_BYTES
        try:
            rel_bytes = self._safe_fsencode(rel_path)
        except Exception:
            rel_bytes = str(rel_path).encode('utf-8', errors='surrogatepass')
        return os.path.join(RESOURCES_PATH_BYTES, rel_bytes)

    def _safe_fsencode(self, value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        try:
            return os.fsencode(value)
        except Exception:
            return str(value).encode('utf-8', errors='surrogatepass')

    def _safe_fsdecode(self, value):
        if isinstance(value, str):
            return value
        try:
            return os.fsdecode(value)
        except Exception:
            return bytes(value).decode('utf-8', errors='surrogatepass')

    def _add_name_and_b64_variants(self, bound_name_map, bound_b64_map, raw_name, fabric_id):
        """Add normalized string variants and base64-of-bytes variants for a given image name into maps."""
        if not raw_name:
            return
        try:
            base = raw_name.split('/')[-1].strip()
        except Exception:
            base = raw_name
        if not base:
            return
        try:
            nfc = unicodedata.normalize('NFC', base)
        except Exception:
            nfc = base
        try:
            nfd = unicodedata.normalize('NFD', base)
        except Exception:
            nfd = nfc

        for key in (nfc, nfc.lower(), nfd, nfd.lower()):
            if not key:
                continue
            if key not in bound_name_map:
                bound_name_map[key] = set()
            if fabric_id is not None:
                bound_name_map[key].add(int(fabric_id))

        # Add multiple byte-encoding variants for more robust matching across
        # filesystem encodings and database-stored strings. Try fs encoding first,
        # then fall back to several common encodings with surrogatepass so that
        # round-trip surrogate bytes are preserved when present on the NAS.
        for variant in (nfc, nfd):
            if not variant:
                continue
            encodings_to_try = []
            try:
                encodings_to_try.append(os.fsencode(variant))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('utf-8', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('gb18030', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('latin-1', errors='surrogatepass'))
            except Exception:
                pass

            # de-duplicate byte variants
            seen = set()
            for b in encodings_to_try:
                if not isinstance(b, (bytes, bytearray)):
                    continue
                if b in seen:
                    continue
                seen.add(b)
                try:
                    b64 = base64.b64encode(b).decode('ascii')
                    if b64 not in bound_b64_map:
                        bound_b64_map[b64] = set()
                    if fabric_id is not None:
                        bound_b64_map[b64].add(int(fabric_id))
                except Exception:
                    continue

    def _is_image_name(self, name):
        """判断是否为图片文件名（兼容 bytes/str）"""
        if isinstance(name, (bytes, bytearray)):
            try:
                name = os.fsdecode(name)
            except Exception:
                name = name.decode('utf-8', errors='ignore')
        return str(name).lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))

    def _to_int(self, value, default=None):
        try:
            return int(value)
        except Exception:
            return default

    def _normalize_fabric_remark(self, remark):
        value = (remark or '').strip()
        allowed = {
            '原图',
            '主图·Swatch',
            '主图·卖点',
            'A+·电脑端',
            'A+·手机端',
            'A+·通用',
        }
        if value in allowed:
            return value
        if value in ('平面原图', '褶皱原图'):
            return '原图'
        if '卖点' in value:
            return '主图·卖点'
        if 'Swatch' in value or 'swatch' in value:
            return '主图·Swatch'
        if 'A+' in value or value.startswith('A＋'):
            if '电脑' in value:
                return 'A+·电脑端'
            if '手机' in value:
                return 'A+·手机端'
            return 'A+·通用'
        return '原图'

    def _build_fabric_image_plan(self, images, fabric_code):
        """为面料图片生成重命名计划和最终入库数据"""
        folder = self._ensure_fabric_folder()
        remark_counters = {}
        planned_images = []
        rename_pairs = []
        missing = []
        not_ready = []

        for idx, img in enumerate(images):
            old_name = (img.get('image_name') or '').strip()
            if not old_name:
                continue

            src_path = os.path.join(folder, self._safe_fsencode(old_name))
            if not os.path.exists(src_path):
                missing.append(old_name)
                continue
            try:
                if os.path.getsize(src_path) <= 0:
                    not_ready.append(old_name)
                    continue
            except Exception:
                not_ready.append(old_name)
                continue

            remark = self._normalize_fabric_remark(img.get('remark'))
            remark_counters[remark] = remark_counters.get(remark, 0) + 1
            index_in_remark = remark_counters[remark]
            new_name = self._rename_fabric_image_with_remark(old_name, fabric_code, remark, index_in_remark)

            planned_images.append({
                'image_name': new_name,
                'remark': remark,
                'sort_order': self._to_int(img.get('sort_order'), idx) if isinstance(img, dict) else idx,
                'is_primary': bool(img.get('is_primary', idx == 0)) if isinstance(img, dict) else (idx == 0),
            })

            if new_name != old_name:
                rename_pairs.append((old_name, new_name))

        return {
            'planned_images': planned_images,
            'rename_pairs': rename_pairs,
            'missing': missing,
            'not_ready': not_ready,
        }

    def _execute_fabric_rename_pairs(self, rename_pairs):
        """安全执行批量重命名，避免目标名冲突（两阶段：先临时名，再目标名）"""
        if not rename_pairs:
            return {'status': 'success', 'rollback_pairs': []}

        folder = self._ensure_fabric_folder()
        normalized = []
        seen_src = set()
        seen_dst = set()
        for src_name, dst_name in rename_pairs:
            src = (src_name or '').strip()
            dst = (dst_name or '').strip()
            if not src or not dst or src == dst:
                continue
            if src in seen_src:
                return {'status': 'error', 'message': f'重复源文件: {src}'}
            if dst in seen_dst:
                return {'status': 'error', 'message': f'目标文件名冲突: {dst}'}
            seen_src.add(src)
            seen_dst.add(dst)
            normalized.append((src, dst))

        if not normalized:
            return {'status': 'success', 'rollback_pairs': []}

        src_set = {src for src, _ in normalized}
        for src, dst in normalized:
            src_path = os.path.join(folder, self._safe_fsencode(src))
            dst_path = os.path.join(folder, self._safe_fsencode(dst))
            if not os.path.exists(src_path):
                return {'status': 'error', 'message': f'源文件不存在: {src}'}
            if dst not in src_set and os.path.exists(dst_path):
                return {'status': 'error', 'message': f'目标文件已存在: {dst}'}

        temp_pairs = []
        for index, (src, dst) in enumerate(normalized):
            token = secrets.token_hex(6)
            temp_name = f".__sitjoy_tmp__{token}_{index}"
            while os.path.exists(os.path.join(folder, self._safe_fsencode(temp_name))):
                token = secrets.token_hex(6)
                temp_name = f".__sitjoy_tmp__{token}_{index}"
            temp_pairs.append((src, temp_name, dst))

        moved_to_temp = []
        moved_to_final = []
        try:
            for src, temp_name, _ in temp_pairs:
                src_path = os.path.join(folder, self._safe_fsencode(src))
                temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                os.rename(src_path, temp_path)
                moved_to_temp.append((src, temp_name))

            for src, temp_name, dst in temp_pairs:
                temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                dst_path = os.path.join(folder, self._safe_fsencode(dst))
                os.rename(temp_path, dst_path)
                moved_to_final.append((src, dst))

            rollback_pairs = [(dst, src) for src, dst in reversed(moved_to_final)]
            return {'status': 'success', 'rollback_pairs': rollback_pairs}
        except Exception as e:
            try:
                final_map = {dst: src for src, dst in moved_to_final}
                for _, dst in reversed(moved_to_final):
                    dst_path = os.path.join(folder, self._safe_fsencode(dst))
                    src = final_map.get(dst)
                    if src and os.path.exists(dst_path):
                        os.rename(dst_path, os.path.join(folder, self._safe_fsencode(src)))
            except Exception:
                pass

            try:
                for src, temp_name in reversed(moved_to_temp):
                    temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                    src_path = os.path.join(folder, self._safe_fsencode(src))
                    if os.path.exists(temp_path):
                        os.rename(temp_path, src_path)
            except Exception:
                pass

            return {'status': 'error', 'message': f'文件重命名失败: {str(e)}'}
    
    def handle_images_api(self, environ, start_response):
        """获取图片列表（用Base64编码路径避免编码问题）"""
        images = []
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            page = int(query_params.get('page', ['1'])[0])
            per_page = min(int(query_params.get('per_page', ['100'])[0]), 200)
            
            # 检查RESOURCES_PATH是否存在
            if not os.path.exists(RESOURCES_PATH_BYTES):
                # 列出/volume1/下的文件夹帮助调试
                try:
                    volume_contents = os.listdir('/volume1') if os.path.exists('/volume1') else []
                    folders_list = [f for f in volume_contents if os.path.isdir(f'/volume1/{f}')]
                    # 用Base64编码文件夹列表以避免编码问题
                    try:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='surrogatepass')).decode('ascii')
                    except Exception:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='ignore')).decode('ascii')
                    return self.send_json({
                        'status': 'error', 
                        'message': 'Path not found',
                        'available_folders_b64': folders_b64
                    }, start_response)
                except:
                    return self.send_json({
                        'status': 'error', 
                        'message': f'Path not found and cannot list volume'
                    }, start_response)
            
            # 扫描文件
            count = 0
            for root, dirs, files in os.walk(RESOURCES_PATH_BYTES):
                for file in files:
                    if self._is_image_name(file):
                        try:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, RESOURCES_PATH_BYTES)
                            
                            # 用Base64编码所有内容（保留文件系统原始字节）
                            path_b64 = self._b64_from_fs(rel_path)
                            filename_b64 = self._b64_from_fs(file)
                            
                            # folder也编码，完全避免中文
                            folder = os.path.dirname(rel_path) or b'root'
                            folder_b64 = self._b64_from_fs(folder)
                            
                            images.append({
                                'id': path_b64,
                                'filename': filename_b64,
                                'folder': folder_b64
                            })
                            count += 1
                        except Exception as e:
                            print(f"File error: {type(e).__name__}")
                            pass
            
            # 分页
            total = len(images)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated = images[start_idx:end_idx]
            
            # 计算总页数
            import math
            total_pages = math.ceil(total / per_page) if total > 0 else 1
            
            # 完全ASCII的响应
            resp = {
                'status': 'success',
                'total': total,
                'page': page,
                'pages': total_pages,
                'count': len(paginated),
                'images': paginated
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print(f"Exception in handle_images_api: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            # 返回错误时，消息也要清理，不含中文
            return self.send_json({
                'status': 'error', 
                'message': f'Error: {type(e).__name__}'
            }, start_response)
    
    def handle_browse_api(self, environ, start_response):
        """浏览目录API：返回指定目录下的文件夹和图片"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('path', [''])[0]
            debug = query_params.get('debug', ['0'])[0] == '1'

            # 解码路径（如果为空则为根目录）
            if path_b64:
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except:
                    return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)
            else:
                rel_path = ''

            # 防止路径遍历
            if '..' in rel_path:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            # 构建完整路径（bytes）
            current_path = self._join_resources(rel_path)

            # 验证路径安全性
            abs_path = os.path.abspath(current_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(current_path):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            folders = []
            images = []

            try:
                debug_items = []
                rel_path_bytes = os.fsencode(rel_path) if rel_path else b''
                with os.scandir(current_path) as it:
                    for entry in it:
                        try:
                            item = entry.name
                            item_bytes = item if isinstance(item, (bytes, bytearray)) else os.fsencode(item)

                            # 跳过系统文件夹
                            if item_bytes.startswith(b'@') or item_bytes.startswith(b'.'):
                                if debug:
                                    debug_items.append({
                                        'name': self._b64_from_fs(item),
                                        'skipped': 'system',
                                        'is_dir': entry.is_dir(follow_symlinks=False),
                                        'is_file': entry.is_file(follow_symlinks=False)
                                    })
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                folder_rel_path = os.path.join(rel_path_bytes, item_bytes) if rel_path_bytes else item_bytes
                                folders.append({
                                    'name': self._b64_from_fs(item_bytes),
                                    'path': self._b64_from_fs(folder_rel_path),
                                    'type': 'folder'
                                })
                            elif entry.is_file(follow_symlinks=False):
                                if self._is_image_name(item_bytes):
                                    image_rel_path = os.path.join(rel_path_bytes, item_bytes) if rel_path_bytes else item_bytes
                                    images.append({
                                        'name': self._b64_from_fs(item_bytes),
                                        'path': self._b64_from_fs(image_rel_path),
                                        'type': 'image'
                                    })
                                elif debug:
                                    debug_items.append({
                                        'name': self._b64_from_fs(item_bytes),
                                        'skipped': 'not_image',
                                        'is_dir': False,
                                        'is_file': True
                                    })
                            elif debug:
                                debug_items.append({
                                    'name': self._b64_from_fs(item_bytes),
                                    'skipped': 'unknown_type',
                                    'is_dir': entry.is_dir(follow_symlinks=False),
                                    'is_file': entry.is_file(follow_symlinks=False)
                                })
                        except Exception as e:
                            print(f"Item error: {type(e).__name__}")
                            if debug:
                                debug_items.append({
                                    'name': 'unknown',
                                    'skipped': f'error:{type(e).__name__}'
                                })
                            pass
            except Exception as e:
                return self.send_json({'status': 'error', 'message': f'Cannot read directory: {type(e).__name__}'}, start_response)

            folders.sort(key=lambda x: x['name'])
            images.sort(key=lambda x: x['name'])

            breadcrumbs = []
            if rel_path:
                rel_path_bytes = os.fsencode(rel_path)
                parts = rel_path_bytes.split(b'/')
                current = b''
                for part in parts:
                    current = os.path.join(current, part) if current else part
                    breadcrumbs.append({
                        'name': self._b64_from_fs(part),
                        'path': self._b64_from_fs(current)
                    })

            resp = {
                'status': 'success',
                'current_path': path_b64,
                'breadcrumbs': breadcrumbs,
                'folders': folders,
                'images': images,
                'total_folders': len(folders),
                'total_images': len(images)
            }

            if debug:
                resp['debug_items'] = debug_items

            return self.send_json(resp, start_response)

        except Exception as e:
            print(f"Browse error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return self.send_json({'status': 'error', 'message': f'Error: {type(e).__name__}'}, start_response)
    
    def handle_image_preview(self, environ, start_response):
        """获取图片预览（接受Base64编码的路径）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('id', [''])[0]
            mode = (query_params.get('mode', [''])[0] or '').strip().lower()
            max_w = self._to_int(query_params.get('w', [''])[0], 0) or 0
            max_h = self._to_int(query_params.get('h', [''])[0], 0) or 0
            quality = self._to_int(query_params.get('q', [''])[0], 0) or 0
            use_compressed = mode in ('thumb', 'compressed') or max_w > 0 or max_h > 0 or quality > 0
            
            if not path_b64:
                return self.send_error(400, 'Missing id parameter', start_response)
            
            # 解码Base64路径。前端可能对文件名做了 UTF-8 编码再 base64，
            # 也可能对文件系统原始 bytes 做 base64。优先尝试使用原始 bytes 直接拼接路径。
            try:
                raw = base64.b64decode(path_b64)
            except Exception:
                return self.send_error(400, 'Invalid id', start_response)

            full_path = None
            # 1) 尝试将 raw 作为相对 bytes 路径直接拼接并检查
            try:
                candidate = os.path.join(RESOURCES_PATH_BYTES, raw)
                abs_candidate = os.path.abspath(candidate)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if abs_candidate.startswith(abs_resources) and os.path.exists(candidate):
                    full_path = candidate
            except Exception:
                full_path = None

            # 2) 回退：把 raw 解为字符串（filesystem decode）再拼接
            if full_path is None:
                try:
                    rel_path = os.fsdecode(raw)
                except Exception:
                    try:
                        rel_path = raw.decode('utf-8', errors='surrogatepass')
                    except Exception:
                        return self.send_error(400, 'Invalid id', start_response)

                # 防止路径遍历
                if '..' in rel_path or rel_path.startswith('/'):
                    return self.send_error(403, 'Invalid path', start_response)

                full_path = self._join_resources(rel_path)
            
            # 验证路径安全性并存在性
            try:
                abs_path = os.path.abspath(full_path)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if not abs_path.startswith(abs_resources):
                    return self.send_error(403, 'Access denied', start_response)
            except Exception:
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_path):
                return self.send_error(404, 'File not found', start_response)
            
            # 读取图片
            mime_path = os.fsdecode(full_path) if isinstance(full_path, (bytes, bytearray)) else full_path
            mime_type, _ = mimetypes.guess_type(mime_path)
            if not mime_type:
                mime_type = 'image/jpeg'

            if use_compressed and Image:
                try:
                    img = Image.open(full_path)
                    if max_w <= 0 and max_h <= 0:
                        max_w, max_h = 360, 360
                    max_w = max(1, max_w) if max_w > 0 else 360
                    max_h = max(1, max_h) if max_h > 0 else 360
                    img.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)

                    if quality <= 0:
                        quality = 72
                    quality = max(35, min(90, quality))

                    output = io.BytesIO()
                    if img.mode not in ('RGB', 'L'):
                        img = img.convert('RGB')
                    img.save(output, format='JPEG', quality=quality, optimize=True)
                    image_data = output.getvalue()
                    mime_type = 'image/jpeg'
                except Exception:
                    with open(full_path, 'rb') as f:
                        image_data = f.read()
            else:
                with open(full_path, 'rb') as f:
                    image_data = f.read()
            
            start_response('200 OK', [
                ('Content-Type', mime_type),
                ('Content-Length', str(len(image_data))),
                ('Cache-Control', 'public, max-age=300')
            ])
            
            return [image_data]
                    
        except Exception as e:
            print("Preview error: " + str(e))
            return self.send_error(500, str(e), start_response)
    
    def handle_rename_api(self, environ, start_response):
        """处理文件重命名（接受Base64编码路径）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8'))

            path_b64 = data.get('id', '')
            new_name_b64 = data.get('new_name_b64', '')

            if not path_b64:
                return self.send_error(400, 'Missing parameters', start_response)

            # 解码路径和新名称
            try:
                old_path = self._fs_from_b64(path_b64)
                new_name = self._fs_from_b64(new_name_b64) if new_name_b64 else ''
            except:
                return self.send_error(400, 'Invalid parameters', start_response)

            if '..' in old_path or ('..' in new_name if new_name else False):
                return self.send_error(403, 'Invalid path', start_response)

            full_old_path = self._join_resources(old_path)

            # 验证安全性
            abs_path = os.path.abspath(full_old_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_old_path):
                return self.send_error(404, 'File not found', start_response)

            # 获取扩展名
            folder = os.path.dirname(full_old_path)
            ext = os.path.splitext(os.path.basename(full_old_path))[1]
            new_name_bytes = os.fsencode(new_name)
            new_filename = new_name_bytes + ext if not new_name_bytes.endswith(ext) else new_name_bytes
            full_new_path = os.path.join(folder, new_filename)

            # 检查新名称是否已存在
            if os.path.exists(full_new_path):
                return self.send_error(409, 'File already exists', start_response)

            # 重命名
            os.rename(full_old_path, full_new_path)

            resp = {
                'status': 'success',
                'message': 'Renamed',
                'new_name': os.fsdecode(new_filename)
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print("Rename error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_move_api(self, environ, start_response):
        """处理文件移动+重命名（目标仅允许根目录下）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8'))

            path_b64 = data.get('id', '')
            new_name_b64 = data.get('new_name_b64', '')
            target_folder_b64 = data.get('target_folder_b64', '')

            if not path_b64 or not new_name_b64:
                return self.send_error(400, 'Missing parameters', start_response)

            try:
                old_path = self._fs_from_b64(path_b64)
                new_name = self._fs_from_b64(new_name_b64)
            except:
                return self.send_error(400, 'Invalid parameters', start_response)

            if '..' in old_path or '..' in new_name:
                return self.send_error(403, 'Invalid path', start_response)

            if target_folder_b64:
                try:
                    target_folder_bytes = base64.b64decode(target_folder_b64)
                except:
                    return self.send_error(400, 'Invalid target folder', start_response)
            else:
                target_folder_bytes = b''

            # 仅允许资源根目录内路径
            if target_folder_bytes.startswith((b'/', b'\\')):
                return self.send_error(403, 'Target folder not allowed', start_response)
            if b'..' in target_folder_bytes.split(b'/') or b'..' in target_folder_bytes.split(b'\\'):
                return self.send_error(403, 'Target folder not allowed', start_response)

            full_old_path = self._join_resources(old_path)

            abs_old = os.path.abspath(full_old_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_old.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_old_path):
                return self.send_error(404, 'File not found', start_response)

            dest_dir = os.path.join(RESOURCES_PATH_BYTES, target_folder_bytes) if target_folder_bytes else os.path.dirname(full_old_path)
            if not os.path.exists(dest_dir) or not os.path.isdir(dest_dir):
                return self.send_error(404, 'Target folder not found', start_response)

            old_basename = os.path.basename(full_old_path)
            ext = os.path.splitext(old_basename)[1]
            if new_name:
                new_name_bytes = os.fsencode(new_name)
                new_filename = new_name_bytes + ext if not new_name_bytes.endswith(ext) else new_name_bytes
            else:
                new_filename = old_basename
            full_new_path = os.path.join(dest_dir, new_filename)

            if os.path.abspath(full_new_path) == os.path.abspath(full_old_path):
                return self.send_error(400, 'No changes', start_response)

            if os.path.exists(full_new_path):
                return self.send_error(409, 'File already exists', start_response)

            os.rename(full_old_path, full_new_path)

            resp = {
                'status': 'success',
                'message': 'Moved',
                'new_name': os.fsdecode(new_filename)
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print("Move error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_upload_api(self, environ, start_response):
        """处理图片上传（multipart/form-data）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=True)
            path_b64 = form.getfirst('path', '')

            if path_b64:
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except Exception:
                    return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)
            else:
                rel_path = ''

            if '..' in rel_path:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            target_dir = self._join_resources(rel_path)

            abs_target = os.path.abspath(target_dir)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_target.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(target_dir):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            if 'file' not in form:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)

            files_field = form['file']
            if isinstance(files_field, list):
                files_list = files_field
            else:
                files_list = [files_field]

            saved = []
            skipped = []
            for item in files_list:
                try:
                    if not item.filename:
                        continue

                    filename = os.path.basename(item.filename)
                    if not self._is_image_name(filename):
                        skipped.append({'name': str(filename), 'reason': 'not_image'})
                        continue

                    try:
                        filename_bytes = os.fsencode(filename)
                    except Exception:
                        filename_bytes = str(filename).encode('utf-8', errors='surrogatepass')

                    dest_path = os.path.join(target_dir, filename_bytes)
                    if os.path.exists(dest_path):
                        skipped.append({'name': str(filename), 'reason': 'exists'})
                        continue

                    with open(dest_path, 'wb') as f:
                        while True:
                            chunk = item.file.read(1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)

                    saved.append(str(filename))
                except Exception as e:
                    skipped.append({'name': str(getattr(item, 'filename', 'unknown')), 'reason': str(e)})

            return self.send_json({'status': 'success', 'count': len(saved), 'files': saved, 'skipped': skipped}, start_response)
        except Exception as e:
            print("Upload error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_download_zip(self, environ, method, start_response):
        """将选中图片/文件夹打包为 zip 下载"""
        try:
            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ)
            items = data.get('items', []) if isinstance(data, dict) else []
            if not items:
                return self.send_json({'status': 'error', 'message': 'No items selected'}, start_response)

            resources_bytes = RESOURCES_PATH_BYTES
            files = set()

            for item in items:
                path_b64 = item.get('path', '') if isinstance(item, dict) else ''
                if not path_b64:
                    continue
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except Exception:
                    continue
                if '..' in rel_path or rel_path.startswith('/'):
                    continue

                full_path = self._join_resources(rel_path)
                abs_path = os.path.abspath(full_path)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if not abs_path.startswith(abs_resources):
                    continue

                if os.path.isdir(full_path):
                    for root, _, filenames in os.walk(full_path):
                        for name in filenames:
                            if not self._is_image_name(name):
                                continue
                            files.add(os.path.join(root, name))
                elif os.path.isfile(full_path):
                    if self._is_image_name(full_path):
                        files.add(full_path)

            if not files:
                return self.send_json({'status': 'error', 'message': 'No images found'}, start_response)

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            tmp_path = tmp.name
            tmp.close()

            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in files:
                    file_bytes = file_path if isinstance(file_path, (bytes, bytearray)) else os.fsencode(file_path)
                    try:
                        rel_bytes = os.path.relpath(file_bytes, resources_bytes)
                    except Exception:
                        rel_bytes = os.path.basename(file_bytes)
                    if rel_bytes.startswith(b'..'):
                        continue
                    arcname = rel_bytes.decode('utf-8', errors='replace').replace('\\', '/')
                    zf.write(os.fsdecode(file_bytes), arcname)

            with open(tmp_path, 'rb') as f:
                data_bytes = f.read()

            try:
                os.remove(tmp_path)
            except Exception:
                pass

            filename = f"sitjoy_download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            start_response('200 OK', [
                ('Content-Type', 'application/zip'),
                ('Content-Disposition', f'attachment; filename="{filename}"'),
                ('Content-Length', str(len(data_bytes)))
            ])
            return [data_bytes]
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _read_json_body(self, environ):
        """读取请求 JSON body"""
        content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
        if content_length <= 0:
            return {}
        body = environ['wsgi.input'].read(content_length)
        if not body:
            return {}
        return json.loads(body.decode('utf-8'))

    def _send_excel_workbook(self, workbook, filename, start_response):
        output = io.BytesIO()
        workbook.save(output)
        data = output.getvalue()
        start_response('200 OK', [
            ('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
            ('Content-Disposition', f'attachment; filename="{filename}"'),
            ('Content-Length', str(len(data)))
        ])
        return [data]

    def _get_db_config(self):
        """从环境变量读取数据库配置"""
        config = {
            'host': os.environ.get('SITJOY_DB_HOST', '127.0.0.1'),
            'user': os.environ.get('SITJOY_DB_USER', 'root'),
            'password': os.environ.get('SITJOY_DB_PASSWORD', ''),
            'database': os.environ.get('SITJOY_DB_NAME', 'sitjoy'),
            'port': int(os.environ.get('SITJOY_DB_PORT', '3306')),
            'charset': 'utf8mb4'
        }
        # 读取本地配置文件（若存在则覆盖）
        file_cfg = self._load_local_db_config()
        if file_cfg:
            for key in ['host', 'user', 'password', 'database', 'port', 'charset']:
                if key in file_cfg and file_cfg[key] not in (None, ''):
                    if key == 'port':
                        try:
                            config[key] = int(file_cfg[key])
                        except Exception:
                            continue
                    else:
                        config[key] = file_cfg[key]
        return config

    def _load_local_db_config(self):
        """读取项目内 db_config.json（可选）"""
        try:
            cfg_path = os.path.join(self.base_path, 'db_config.json')
            if not os.path.exists(cfg_path):
                return None
            with open(cfg_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def _get_db_connection(self):
        if not pymysql:
            raise RuntimeError(f"PyMySQL not available: {_pymysql_import_error}")
        cfg = self._get_db_config()
        return pymysql.connect(
            host=cfg['host'],
            user=cfg['user'],
            password=cfg['password'],
            database=cfg['database'],
            port=cfg['port'],
            charset=cfg['charset'],
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )

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
        if self._category_ready:
            return
        with self._schema_ensure_lock:
            if self._category_ready:
                return
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
        self._category_ready = True

    def _ensure_fabric_table(self):
        if self._fabric_ready:
            return
        with self._schema_ensure_lock:
            if self._fabric_ready:
                return
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
            is_primary TINYINT(1) NOT NULL DEFAULT 0,
            remark VARCHAR(50) NULL DEFAULT NULL COMMENT '备注类型：平面原图/褶皱原图/卖点图',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_images_fabric (fabric_id),
            INDEX idx_fabric_images_primary (fabric_id, is_primary),
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
                        INSERT INTO fabric_images (fabric_id, image_name, sort_order, is_primary)
                        SELECT fm.id, fm.image_name, 0, 1
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
                
                # 添加 remark 字段用于图片类型标注
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
                        AFTER is_primary
                        """
                    )
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_images'
                      AND COLUMN_NAME = 'sort_order'
                    """
                )
                row = cur.fetchone() or {}
                if int(row.get('cnt') or 0) == 0:
                    cur.execute("ALTER TABLE fabric_images ADD COLUMN sort_order INT UNSIGNED NOT NULL DEFAULT 0 AFTER image_name")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_images'
                      AND COLUMN_NAME = 'is_primary'
                    """
                )
                row = cur.fetchone() or {}
                if int(row.get('cnt') or 0) == 0:
                    cur.execute("ALTER TABLE fabric_images ADD COLUMN is_primary TINYINT(1) NOT NULL DEFAULT 0 AFTER sort_order")
                try:
                    cur.execute("ALTER TABLE fabric_images ADD INDEX idx_fabric_images_primary (fabric_id, is_primary)")
                except Exception:
                    pass
        self._fabric_ready = True

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

    def _ensure_amazon_account_health_table(self):
        if self._amazon_account_health_ready:
            return
        self._ensure_shops_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_account_health (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NOT NULL,
            account_health_rating INT NOT NULL,
            suspected_ip_infringement INT NOT NULL DEFAULT 0,
            intellectual_property_complaints INT NOT NULL DEFAULT 0,
            authenticity_customer_complaints INT NOT NULL DEFAULT 0,
            condition_customer_complaints INT NOT NULL DEFAULT 0,
            food_safety_issues INT NOT NULL DEFAULT 0,
            listing_policy_violations INT NOT NULL DEFAULT 0,
            restricted_product_policy_violations INT NOT NULL DEFAULT 0,
            customer_review_policy_violations INT NOT NULL DEFAULT 0,
            other_policy_violations INT NOT NULL DEFAULT 0,
            regulatory_compliance_issues INT NOT NULL DEFAULT 0,
            order_defect_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            negative_feedback_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            a_to_z_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            chargeback_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            late_shipment_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            pre_fulfillment_cancel_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            valid_tracking_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            on_time_delivery_rate DECIMAL(8,4) NOT NULL DEFAULT 0,
            record_datetime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            remark VARCHAR(500) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_aah_shop_date (shop_id, record_datetime),
            INDEX idx_aah_record_datetime (record_datetime),
            CONSTRAINT fk_aah_shop FOREIGN KEY (shop_id)
                REFERENCES shops(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_account_health_ready = True

    def _ensure_amazon_ad_subtypes_table(self):
        if self._amazon_ad_subtypes_ready:
            return
        self._ensure_amazon_ad_operation_types_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtypes (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            description VARCHAR(255) NOT NULL,
            ad_class VARCHAR(8) NOT NULL DEFAULT 'SP',
            subtype_code VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_subtype (ad_class, subtype_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        relation_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtype_operation_types (
            subtype_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (subtype_id, operation_type_id),
            CONSTRAINT fk_ad_subtype_op_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype_op_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(relation_sql)
        self._amazon_ad_subtypes_ready = True

    def _ensure_amazon_ad_operation_types_table(self):
        if self._amazon_ad_operation_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_operation_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            apply_portfolio TINYINT(1) NOT NULL DEFAULT 1,
            apply_campaign TINYINT(1) NOT NULL DEFAULT 1,
            apply_group TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_reason_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_operation_reasons (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            operation_type_id INT UNSIGNED NOT NULL,
            reason_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_op_reason (operation_type_id, reason_name),
            INDEX idx_ad_op_reason_type (operation_type_id),
            CONSTRAINT fk_ad_op_reason_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
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
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_portfolio'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_portfolio TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_campaign'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_campaign TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_group'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_group TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(create_reason_sql)
        self._amazon_ad_operation_types_ready = True

    def _ensure_amazon_ad_tables(self):
        if self._amazon_ad_ready:
            return
        self._ensure_product_table()
        self._ensure_category_table()
        self._ensure_amazon_ad_subtypes_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ad_level VARCHAR(16) NOT NULL,
            sku_family_id INT UNSIGNED NULL,
            portfolio_id INT UNSIGNED NULL,
            campaign_id INT UNSIGNED NULL,
            strategy_code VARCHAR(8) NULL,
            subtype_id INT UNSIGNED NULL,
            name VARCHAR(255) NOT NULL,
            is_shared_budget TINYINT(1) NULL,
            status VARCHAR(16) NULL,
            budget DECIMAL(12,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_level (ad_level),
            INDEX idx_ad_sku (sku_family_id),
            INDEX idx_ad_portfolio (portfolio_id),
            INDEX idx_ad_campaign (campaign_id),
            INDEX idx_ad_subtype (subtype_id),
            CONSTRAINT fk_ad_sku FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_ad_portfolio FOREIGN KEY (portfolio_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_campaign FOREIGN KEY (campaign_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_ready = True

    def _ensure_amazon_ad_delivery_table(self):
        if self._amazon_ad_delivery_ready:
            return
        self._ensure_amazon_ad_tables()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_deliveries (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            status VARCHAR(16) NOT NULL DEFAULT '启动',
            ad_item_id INT UNSIGNED NOT NULL,
            delivery_desc VARCHAR(255) NOT NULL,
            bid_value VARCHAR(32) NULL,
            observe_interval VARCHAR(64) NULL,
            next_observe_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_delivery_item (ad_item_id),
            INDEX idx_ad_delivery_status (status),
            INDEX idx_ad_delivery_next_observe (next_observe_at),
            CONSTRAINT fk_ad_delivery_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_delivery_ready = True

    def _ensure_amazon_ad_product_table(self):
        if self._amazon_ad_product_ready:
            return
        self._ensure_amazon_ad_tables()
        self._ensure_sales_product_tables()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            status VARCHAR(16) NOT NULL DEFAULT '启动',
            ad_item_id INT UNSIGNED NOT NULL,
            sales_product_id INT UNSIGNED NOT NULL,
            observe_interval VARCHAR(64) NULL,
            next_observe_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_product_item (ad_item_id),
            INDEX idx_ad_product_sales (sales_product_id),
            INDEX idx_ad_product_status (status),
            INDEX idx_ad_product_next_observe (next_observe_at),
            CONSTRAINT fk_ad_product_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_product_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_product_ready = True

    def _ensure_amazon_ad_adjustment_table(self):
        if self._amazon_ad_adjustment_ready:
            return
        self._ensure_amazon_ad_tables()
        self._ensure_amazon_ad_operation_types_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_adjustments (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            adjust_date DATETIME NOT NULL,
            ad_item_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            target_object VARCHAR(255) NOT NULL,
            before_value VARCHAR(64) NULL,
            after_value VARCHAR(64) NULL,
            reason_id INT UNSIGNED NULL,
            start_time DATETIME NULL,
            end_time DATETIME NULL,
            impressions VARCHAR(32) NULL,
            clicks VARCHAR(32) NULL,
            cost VARCHAR(32) NULL,
            orders VARCHAR(32) NULL,
            sales VARCHAR(32) NULL,
            acos VARCHAR(32) NULL,
            cpc VARCHAR(32) NULL,
            ctr VARCHAR(32) NULL,
            cvr VARCHAR(32) NULL,
            attribution_checked TINYINT(1) NOT NULL DEFAULT 0,
            attribution_orders VARCHAR(32) NULL,
            attribution_sales VARCHAR(32) NULL,
            remark VARCHAR(255) NULL,
            is_quick_submit TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ad_adjustment_ad_item (ad_item_id),
            INDEX idx_ad_adjustment_operation (operation_type_id),
            INDEX idx_ad_adjustment_reason (reason_id),
            INDEX idx_ad_adjustment_date (adjust_date),
            CONSTRAINT fk_ad_adjustment_item FOREIGN KEY (ad_item_id)
                REFERENCES amazon_ad_items(id) ON DELETE RESTRICT,
            CONSTRAINT fk_ad_adjustment_operation FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_ad_adjustment_reason FOREIGN KEY (reason_id)
                REFERENCES amazon_ad_operation_reasons(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_adjustment_ready = True

    def _ensure_amazon_keyword_tables(self):
        if self._amazon_keyword_ready:
            return
        self._ensure_category_table()
        self._ensure_product_table()

        create_keywords_sql = """
        CREATE TABLE IF NOT EXISTS amazon_keywords (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_id INT UNSIGNED NOT NULL,
            user_search_term VARCHAR(255) NOT NULL,
            search_rank INT NULL,
            rank_updated_at DATETIME NULL,
            previous_search_rank INT NULL,
            previous_rank_updated_at DATETIME NULL,
            top_click_asin1 VARCHAR(64) NULL,
            top_click_asin1_click_share VARCHAR(32) NULL,
            top_click_asin1_conversion_share VARCHAR(32) NULL,
            top_click_asin2 VARCHAR(64) NULL,
            top_click_asin2_click_share VARCHAR(32) NULL,
            top_click_asin2_conversion_share VARCHAR(32) NULL,
            top_click_asin3 VARCHAR(64) NULL,
            top_click_asin3_click_share VARCHAR(32) NULL,
            top_click_asin3_conversion_share VARCHAR(32) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_amazon_keyword_term (user_search_term),
            INDEX idx_amazon_keyword_category (category_id),
            INDEX idx_amazon_keyword_rank_updated (rank_updated_at),
            CONSTRAINT fk_amazon_keyword_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_tags_sql = """
        CREATE TABLE IF NOT EXISTS amazon_keyword_tags (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_id INT UNSIGNED NOT NULL,
            tag_name VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_keyword_tag (category_id, tag_name),
            INDEX idx_keyword_tag_category (category_id),
            CONSTRAINT fk_keyword_tag_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_tag_rel_sql = """
        CREATE TABLE IF NOT EXISTS amazon_keyword_tag_rel (
            keyword_id INT UNSIGNED NOT NULL,
            tag_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (keyword_id, tag_id),
            CONSTRAINT fk_keyword_tag_rel_keyword FOREIGN KEY (keyword_id)
                REFERENCES amazon_keywords(id) ON DELETE CASCADE,
            CONSTRAINT fk_keyword_tag_rel_tag FOREIGN KEY (tag_id)
                REFERENCES amazon_keyword_tags(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_sku_rel_sql = """
        CREATE TABLE IF NOT EXISTS amazon_keyword_sku_rel (
            keyword_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            relevance_score TINYINT UNSIGNED NOT NULL DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (keyword_id, sku_family_id),
            INDEX idx_keyword_sku_rel_sku (sku_family_id),
            CONSTRAINT fk_keyword_sku_rel_keyword FOREIGN KEY (keyword_id)
                REFERENCES amazon_keywords(id) ON DELETE CASCADE,
            CONSTRAINT fk_keyword_sku_rel_sku FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_keywords_sql)
                cur.execute(create_tags_sql)
                cur.execute(create_tag_rel_sql)
                cur.execute(create_sku_rel_sql)

        self._amazon_keyword_ready = True

    def _ensure_certification_table(self):
        if getattr(self, '_certification_ready', False):
            return
        with self._schema_ensure_lock:
            if getattr(self, '_certification_ready', False):
                return
            create_sql = """
            CREATE TABLE IF NOT EXISTS certifications (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(128) NOT NULL UNIQUE,
                icon_name VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                          AND TABLE_NAME = 'certifications'
                          AND COLUMN_NAME = 'icon_name'
                        """
                    )
                    row = cur.fetchone() or {}
                    if int(row.get('cnt') or 0) == 0:
                        cur.execute("ALTER TABLE certifications ADD COLUMN icon_name VARCHAR(255) NULL AFTER name")
            self._certification_ready = True
            self.__class__._schema_ready_cache['certification'] = True

    def _ensure_features_table(self):
        self._ensure_category_table()
        create_features = """
        CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_feature_categories = """
        CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_features)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'features'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE features ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(create_feature_categories)

    def _ensure_order_product_tables(self):
        if self._order_product_ready:
            return
        self._ensure_product_table()
        self._ensure_fabric_table()
        self._ensure_category_table()
        self._ensure_certification_table()
        self._ensure_materials_table()

        create_order_products = """
        CREATE TABLE IF NOT EXISTS order_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku VARCHAR(64) NOT NULL UNIQUE,
            sku_family_id INT UNSIGNED NULL,
            version_no VARCHAR(64) NOT NULL,
            fabric_id INT UNSIGNED NULL,
            spec_qty_short VARCHAR(128) NOT NULL,
            contents_desc_en VARCHAR(255) NULL,
            is_iteration TINYINT(1) NOT NULL DEFAULT 0,
            is_dachene_product TINYINT(1) NOT NULL DEFAULT 0,
            is_on_market TINYINT(1) NOT NULL DEFAULT 1,
            source_order_product_id INT UNSIGNED NULL,
            finished_length_in DECIMAL(10,2) NULL,
            finished_width_in DECIMAL(10,2) NULL,
            finished_height_in DECIMAL(10,2) NULL,
            net_weight_lbs DECIMAL(10,2) NULL,
            package_length_in DECIMAL(10,2) NULL,
            package_width_in DECIMAL(10,2) NULL,
            package_height_in DECIMAL(10,2) NULL,
            gross_weight_lbs DECIMAL(10,2) NULL,
            cost_usd DECIMAL(10,2) NULL,
            carton_qty INT UNSIGNED NULL,
            package_size_class VARCHAR(64) NULL,
            last_mile_avg_freight_usd DECIMAL(10,2) NULL,
            factory_wip_stock INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sku_family (sku_family_id),
            INDEX idx_fabric (fabric_id),
            INDEX idx_source_order_product (source_order_product_id),
            CONSTRAINT fk_order_products_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_source FOREIGN KEY (source_order_product_id)
                REFERENCES order_products(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_materials = """
        CREATE TABLE IF NOT EXISTS order_product_materials (
            order_product_id INT UNSIGNED NOT NULL,
            material_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, material_id),
            CONSTRAINT fk_opm_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opm_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_features = """
        CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_feature_categories = """
        CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_features = """
        CREATE TABLE IF NOT EXISTS order_product_features (
            order_product_id INT UNSIGNED NOT NULL,
            feature_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, feature_id),
            CONSTRAINT fk_opf_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opf_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_certifications = """
        CREATE TABLE IF NOT EXISTS order_product_certifications (
            order_product_id INT UNSIGNED NOT NULL,
            certification_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, certification_id),
            CONSTRAINT fk_opc_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opc_certification FOREIGN KEY (certification_id)
                REFERENCES certifications(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_shipping_plans = """
        CREATE TABLE IF NOT EXISTS order_product_shipping_plans (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            order_product_id INT UNSIGNED NOT NULL,
            plan_name VARCHAR(128) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_order_plan_name (order_product_id, plan_name),
            INDEX idx_ops_order (order_product_id),
            CONSTRAINT fk_ops_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_shipping_plan_items = """
        CREATE TABLE IF NOT EXISTS order_product_shipping_plan_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shipping_plan_id INT UNSIGNED NOT NULL,
            substitute_order_product_id INT UNSIGNED NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            sort_order INT UNSIGNED NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_opsi_unique (shipping_plan_id, substitute_order_product_id, sort_order),
            INDEX idx_opsi_plan (shipping_plan_id),
            CONSTRAINT fk_opsi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE CASCADE,
            CONSTRAINT fk_opsi_sub_order FOREIGN KEY (substitute_order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_order_products)
                cur.execute(create_order_product_materials)
                cur.execute(create_features)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'features'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE features ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(create_feature_categories)
                cur.execute(create_order_product_features)
                cur.execute(create_order_product_certifications)
                cur.execute(create_order_product_shipping_plans)
                cur.execute(create_order_product_shipping_plan_items)
                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'order_product_shipping_plans'
                          AND COLUMN_NAME = 'is_default'
                        """
                    )
                    row = cur.fetchone() or {}
                    if int(row.get('cnt') or 0) > 0:
                        cur.execute("ALTER TABLE order_product_shipping_plans DROP COLUMN is_default")
                except Exception:
                    pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'dachene_yuncang_no'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN dachene_yuncang_no")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'spec_qty'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN spec_qty")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'listing_image_b64'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN listing_image_b64")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_iteration'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_iteration TINYINT(1) NOT NULL DEFAULT 0")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_dachene_product'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_dachene_product TINYINT(1) NOT NULL DEFAULT 0 AFTER is_iteration")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_on_market'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_on_market TINYINT(1) NOT NULL DEFAULT 1 AFTER is_dachene_product")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'contents_desc_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN contents_desc_en VARCHAR(255) NULL AFTER spec_qty_short")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'factory_wip_stock'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN factory_wip_stock INT NOT NULL DEFAULT 0 AFTER last_mile_avg_freight_usd")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'source_order_product_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN source_order_product_id INT UNSIGNED NULL")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE order_products ADD INDEX idx_source_order_product (source_order_product_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE order_products
                            ADD CONSTRAINT fk_order_products_source
                            FOREIGN KEY (source_order_product_id) REFERENCES order_products(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass

        self._order_product_ready = True

    def _ensure_sales_parent_tables(self):
        if self._sales_parent_ready:
            return
        with self._schema_ensure_lock:
            if self._sales_parent_ready:
                return
        self._ensure_shops_table()
        create_sales_parents = """
        CREATE TABLE IF NOT EXISTS sales_parents (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            parent_code VARCHAR(64) NOT NULL UNIQUE,
            is_enabled TINYINT(1) NOT NULL DEFAULT 1,
            shop_id INT UNSIGNED NULL,
            sku_marker VARCHAR(128) NULL,
            estimated_refund_rate DECIMAL(8,4) NULL,
            estimated_discount_rate DECIMAL(8,4) NULL,
            commission_rate DECIMAL(8,4) NULL,
            estimated_acoas DECIMAL(8,4) NULL,
            sales_title VARCHAR(200) NULL,
            sales_intro VARCHAR(500) NULL,
            sales_bullet_1 VARCHAR(500) NULL,
            sales_bullet_2 VARCHAR(500) NULL,
            sales_bullet_3 VARCHAR(500) NULL,
            sales_bullet_4 VARCHAR(500) NULL,
            sales_bullet_5 VARCHAR(500) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_parent_code (parent_code),
            INDEX idx_parent_shop (shop_id),
            CONSTRAINT fk_sales_parents_shop FOREIGN KEY (shop_id)
                REFERENCES shops(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sales_parents)
                migration_columns = [
                    ("is_enabled", "ALTER TABLE sales_parents ADD COLUMN is_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER parent_code"),
                    ("shop_id", "ALTER TABLE sales_parents ADD COLUMN shop_id INT UNSIGNED NULL AFTER is_enabled"),
                    ("sku_marker", "ALTER TABLE sales_parents ADD COLUMN sku_marker VARCHAR(128) NULL AFTER parent_code"),
                    ("sales_title", "ALTER TABLE sales_parents ADD COLUMN sales_title VARCHAR(200) NULL AFTER estimated_acoas"),
                    ("sales_intro", "ALTER TABLE sales_parents ADD COLUMN sales_intro VARCHAR(500) NULL AFTER sales_title"),
                    ("sales_bullet_1", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_1 VARCHAR(500) NULL AFTER sales_intro"),
                    ("sales_bullet_2", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_2 VARCHAR(500) NULL AFTER sales_bullet_1"),
                    ("sales_bullet_3", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_3 VARCHAR(500) NULL AFTER sales_bullet_2"),
                    ("sales_bullet_4", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_4 VARCHAR(500) NULL AFTER sales_bullet_3"),
                    ("sales_bullet_5", "ALTER TABLE sales_parents ADD COLUMN sales_bullet_5 VARCHAR(500) NULL AFTER sales_bullet_4")
                ]
                for col_name, alter_sql in migration_columns:
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA=DATABASE()
                              AND TABLE_NAME='sales_parents'
                              AND COLUMN_NAME=%s
                            """,
                            (col_name,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) == 0:
                            cur.execute(alter_sql)
                    except Exception:
                        pass
                try:
                    cur.execute("ALTER TABLE sales_parents ADD INDEX idx_parent_shop (shop_id)")
                except Exception:
                    pass
                try:
                    cur.execute(
                        """
                        ALTER TABLE sales_parents
                        ADD CONSTRAINT fk_sales_parents_shop
                        FOREIGN KEY (shop_id) REFERENCES shops(id)
                        ON DELETE SET NULL
                        """
                    )
                except Exception:
                    pass
            self._sales_parent_ready = True
            self.__class__._schema_ready_cache['sales_parent'] = True

    def _ensure_sales_product_tables(self):
        if self._sales_product_ready:
            return
        self._ensure_shops_table()
        self._ensure_sales_parent_tables()
        self._ensure_amazon_ad_tables()
        self._ensure_order_product_tables()

        create_sales_products = """
        CREATE TABLE IF NOT EXISTS sales_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NULL,
            portfolio_id INT UNSIGNED NOT NULL,
            platform_sku VARCHAR(128) NOT NULL UNIQUE,
            product_status VARCHAR(16) NOT NULL DEFAULT 'enabled',
            sku_family_id INT UNSIGNED NULL,
            parent_id INT UNSIGNED NULL,
            child_code VARCHAR(64) NULL,
            dachene_yuncang_no VARCHAR(128) NULL,
            fabric VARCHAR(255) NULL,
            spec_name VARCHAR(255) NULL,
            sales_title VARCHAR(200) NULL,
            sale_price_usd DECIMAL(10,2) NULL,
            warehouse_cost_usd DECIMAL(10,2) NULL,
            last_mile_cost_usd DECIMAL(10,2) NULL,
            package_length_in DECIMAL(10,2) NULL,
            package_width_in DECIMAL(10,2) NULL,
            package_height_in DECIMAL(10,2) NULL,
            net_weight_lbs DECIMAL(10,2) NULL,
            gross_weight_lbs DECIMAL(10,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sp_shop (shop_id),
            INDEX idx_sp_sku_family (sku_family_id),
            INDEX idx_sp_parent (parent_id),
            INDEX idx_sp_portfolio (portfolio_id),
            CONSTRAINT fk_sp_shop FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_sku_family FOREIGN KEY (sku_family_id) REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_parent FOREIGN KEY (parent_id) REFERENCES sales_parents(id) ON DELETE SET NULL,
            CONSTRAINT fk_sp_portfolio FOREIGN KEY (portfolio_id) REFERENCES amazon_ad_items(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_sales_order_links = """
        CREATE TABLE IF NOT EXISTS sales_product_order_links (
            sales_product_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            PRIMARY KEY (sales_product_id, order_product_id),
            CONSTRAINT fk_spol_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_spol_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sales_products)
                cur.execute(create_sales_order_links)
                
                # 删除 portfolio_id 字段的迁移
                try:
                    cur.execute("""
                        SELECT COLUMN_NAME FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                        AND TABLE_NAME='sales_products'
                        AND COLUMN_NAME='portfolio_id'
                    """)
                    if cur.fetchone():
                        # 先删除外键约束
                        cur.execute("""
                            SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND CONSTRAINT_NAME != 'PRIMARY'
                        """)
                        fk_row = cur.fetchone()
                        if fk_row:
                            fk_name = fk_row['CONSTRAINT_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP FOREIGN KEY {fk_name}")
                        # 删除索引（如果存在）
                        cur.execute("""
                            SELECT INDEX_NAME FROM information_schema.STATISTICS
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND INDEX_NAME != 'PRIMARY'
                        """)
                        idx_row = cur.fetchone()
                        if idx_row:
                            idx_name = idx_row['INDEX_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP INDEX {idx_name}")
                        # 最后删除列
                        cur.execute("ALTER TABLE sales_products DROP COLUMN portfolio_id")
                except Exception:
                    pass

                # 兼容迁移：旧字段重命名/新增
                migration_columns = [
                    ("product_status", "ALTER TABLE sales_products ADD COLUMN product_status VARCHAR(16) NOT NULL DEFAULT 'enabled' AFTER platform_sku"),
                    ("sku_family_id", "ALTER TABLE sales_products ADD COLUMN sku_family_id INT UNSIGNED NULL AFTER platform_sku"),
                    ("parent_id", "ALTER TABLE sales_products ADD COLUMN parent_id INT UNSIGNED NULL AFTER platform_sku"),
                    ("child_code", "ALTER TABLE sales_products ADD COLUMN child_code VARCHAR(64) NULL AFTER parent_id"),
                    ("dachene_yuncang_no", "ALTER TABLE sales_products ADD COLUMN dachene_yuncang_no VARCHAR(128) NULL AFTER child_code"),
                    ("sales_title", "ALTER TABLE sales_products ADD COLUMN sales_title VARCHAR(200) NULL AFTER spec_name"),
                    ("sale_price_usd", "ALTER TABLE sales_products ADD COLUMN sale_price_usd DECIMAL(10,2) NULL AFTER spec_name"),
                    ("warehouse_cost_usd", "ALTER TABLE sales_products ADD COLUMN warehouse_cost_usd DECIMAL(10,2) NULL AFTER sale_price_usd"),
                    ("last_mile_cost_usd", "ALTER TABLE sales_products ADD COLUMN last_mile_cost_usd DECIMAL(10,2) NULL AFTER warehouse_cost_usd"),
                    ("package_length_in", "ALTER TABLE sales_products ADD COLUMN package_length_in DECIMAL(10,2) NULL AFTER last_mile_cost_usd"),
                    ("package_width_in", "ALTER TABLE sales_products ADD COLUMN package_width_in DECIMAL(10,2) NULL AFTER package_length_in"),
                    ("package_height_in", "ALTER TABLE sales_products ADD COLUMN package_height_in DECIMAL(10,2) NULL AFTER package_width_in"),
                    ("net_weight_lbs", "ALTER TABLE sales_products ADD COLUMN net_weight_lbs DECIMAL(10,2) NULL AFTER package_height_in"),
                    ("gross_weight_lbs", "ALTER TABLE sales_products ADD COLUMN gross_weight_lbs DECIMAL(10,2) NULL AFTER net_weight_lbs")
                ]
                for col_name, alter_sql in migration_columns:
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA=DATABASE()
                              AND TABLE_NAME='sales_products'
                              AND COLUMN_NAME=%s
                            """,
                            (col_name,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) == 0:
                            cur.execute(alter_sql)
                    except Exception:
                        pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.STATISTICS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND INDEX_NAME='idx_sp_sku_family'
                        """
                    )
                    idx_row = cur.fetchone()
                    if not idx_row or idx_row.get('cnt', 0) == 0:
                        cur.execute("ALTER TABLE sales_products ADD INDEX idx_sp_sku_family (sku_family_id)")
                except Exception:
                    pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.KEY_COLUMN_USAGE
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND CONSTRAINT_NAME='fk_sp_sku_family'
                        """
                    )
                    fk_row = cur.fetchone()
                    if not fk_row or fk_row.get('cnt', 0) == 0:
                        cur.execute(
                            """
                            ALTER TABLE sales_products
                            ADD CONSTRAINT fk_sp_sku_family
                            FOREIGN KEY (sku_family_id) REFERENCES product_families(id)
                            ON DELETE SET NULL
                            """
                        )
                except Exception:
                    pass

                # 旧 parent_asin/child_asin 字段迁移
                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND COLUMN_NAME='child_asin'
                        """
                    )
                    row = cur.fetchone()
                    if row and row.get('cnt', 0) > 0:
                        cur.execute("UPDATE sales_products SET child_code = child_asin WHERE child_code IS NULL AND child_asin IS NOT NULL")
                        cur.execute("ALTER TABLE sales_products DROP COLUMN child_asin")
                except Exception:
                    pass

                try:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='sales_products'
                          AND COLUMN_NAME='parent_asin'
                        """
                    )
                    row = cur.fetchone()
                    if row and row.get('cnt', 0) > 0:
                        cur.execute(
                            """
                            INSERT IGNORE INTO sales_parents (parent_code)
                            SELECT DISTINCT parent_asin FROM sales_products
                            WHERE parent_asin IS NOT NULL AND parent_asin <> ''
                            """
                        )
                        cur.execute(
                            """
                            UPDATE sales_products sp
                            JOIN sales_parents p ON p.parent_code = sp.parent_asin
                            SET sp.parent_id = p.id
                            WHERE sp.parent_id IS NULL
                            """
                        )
                        cur.execute("ALTER TABLE sales_products DROP COLUMN parent_asin")
                except Exception:
                    pass

                for old_col in ['assembled_length_in', 'assembled_width_in', 'assembled_height_in']:
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA=DATABASE()
                              AND TABLE_NAME='sales_products'
                              AND COLUMN_NAME=%s
                            """,
                            (old_col,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) > 0:
                            cur.execute(f"ALTER TABLE sales_products DROP COLUMN {old_col}")
                    except Exception:
                        pass


                try:
                    cur.execute("ALTER TABLE sales_products ADD INDEX idx_sp_parent (parent_id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_products MODIFY COLUMN shop_id INT UNSIGNED NULL")
                except Exception:
                    pass
                try:
                    cur.execute(
                        """
                        ALTER TABLE sales_products
                        ADD CONSTRAINT fk_sp_parent FOREIGN KEY (parent_id)
                        REFERENCES sales_parents(id) ON DELETE SET NULL
                        """
                    )
                except Exception:
                    pass
        self._sales_product_ready = True

    def _ensure_sales_order_registration_tables(self):
        if self._sales_order_registration_ready:
            return
        with self._schema_ensure_lock:
            if self._sales_order_registration_ready:
                return
        self._ensure_sales_product_tables()
        self._ensure_order_product_tables()
        self._ensure_shops_table()

        create_orders = """
        CREATE TABLE IF NOT EXISTS sales_order_registrations (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NULL,
            order_no VARCHAR(128) NOT NULL,
            order_date DATE NULL,
            customer_name VARCHAR(128) NULL,
            phone VARCHAR(64) NULL,
            zip_code VARCHAR(16) NULL,
            address VARCHAR(255) NULL,
            city VARCHAR(64) NULL,
            state VARCHAR(32) NULL,
            shipping_status VARCHAR(32) NOT NULL DEFAULT 'pending',
            is_review_invited TINYINT(1) NOT NULL DEFAULT 0,
            is_logistics_emailed TINYINT(1) NOT NULL DEFAULT 0,
            compensation_action VARCHAR(255) NULL,
            remark TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sor_shop (shop_id),
            INDEX idx_sor_order_no (order_no),
            INDEX idx_sor_date (order_date),
            CONSTRAINT fk_sor_shop FOREIGN KEY (shop_id)
                REFERENCES shops(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_platform_items = """
        CREATE TABLE IF NOT EXISTS sales_order_registration_platform_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            sales_product_id INT UNSIGNED NULL,
            platform_sku VARCHAR(128) NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            shipping_plan_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorpi_registration (registration_id),
            INDEX idx_sorpi_sales (sales_product_id),
            INDEX idx_sorpi_plan (shipping_plan_id),
            CONSTRAINT fk_sorpi_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE,
            CONSTRAINT fk_sorpi_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE SET NULL,
            CONSTRAINT fk_sorpi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_shipment_items = """
        CREATE TABLE IF NOT EXISTS sales_order_registration_shipment_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NULL,
            order_sku VARCHAR(64) NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            source_type VARCHAR(16) NOT NULL DEFAULT 'manual',
            shipping_plan_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorsi_registration (registration_id),
            INDEX idx_sorsi_order_product (order_product_id),
            INDEX idx_sorsi_plan (shipping_plan_id),
            CONSTRAINT fk_sorsi_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE,
            CONSTRAINT fk_sorsi_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE SET NULL,
            CONSTRAINT fk_sorsi_plan FOREIGN KEY (shipping_plan_id)
                REFERENCES order_product_shipping_plans(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_logistics_items = """
        CREATE TABLE IF NOT EXISTS sales_order_registration_logistics_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            registration_id INT UNSIGNED NOT NULL,
            shipping_carrier VARCHAR(128) NULL,
            tracking_no VARCHAR(255) NULL,
            sort_order INT UNSIGNED NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sorli_registration (registration_id),
            INDEX idx_sorli_tracking (tracking_no(128)),
            CONSTRAINT fk_sorli_registration FOREIGN KEY (registration_id)
                REFERENCES sales_order_registrations(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_orders)
                cur.execute(create_platform_items)
                cur.execute(create_shipment_items)
                cur.execute(create_logistics_items)
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_shop_order (shop_id, order_no)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_customer_name (customer_name)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registrations ADD INDEX idx_sor_phone (phone)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_logistics_items ADD INDEX idx_sorli_carrier_tracking (shipping_carrier, tracking_no(128))")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_platform_items ADD INDEX idx_sorpi_registration_id_id (registration_id, id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_shipment_items ADD INDEX idx_sorsi_registration_id_id (registration_id, id)")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE sales_order_registration_logistics_items ADD INDEX idx_sorli_registration_sort_id (registration_id, sort_order, id)")
                except Exception:
                    pass
                for old_col in ('is_cancelled', 'shipping_carrier', 'tracking_no'):
                    try:
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'sales_order_registrations'
                              AND COLUMN_NAME = %s
                            """,
                            (old_col,)
                        )
                        row = cur.fetchone() or {}
                        if int(row.get('cnt') or 0) > 0:
                            cur.execute(f"ALTER TABLE sales_order_registrations DROP COLUMN {old_col}")
                    except Exception:
                        pass
            self._sales_order_registration_ready = True
            self.__class__._schema_ready_cache['sales_order_registration'] = True

    def _ensure_todo_tables(self, lightweight=False):
        if self._todo_ready and (lightweight or self._todo_schema_migrated):
            return

        with self._todo_ensure_lock:
            if self._todo_ready and (lightweight or self._todo_schema_migrated):
                return

            create_users = """
            CREATE TABLE IF NOT EXISTS users (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(128) NULL,
                phone VARCHAR(64) NULL,
                birthday DATE NULL,
                is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
                can_grant_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
                page_permissions LONGTEXT NULL,
                is_approved TINYINT(1) NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_birthday (birthday),
                INDEX idx_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            create_todos = """
            CREATE TABLE IF NOT EXISTS todos (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                detail TEXT NULL,
                start_date DATE NOT NULL,
                due_date DATE NOT NULL,
                reminder_interval_days INT UNSIGNED NOT NULL DEFAULT 1,
                last_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                next_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                is_recurring TINYINT UNSIGNED NOT NULL DEFAULT 0,
                status VARCHAR(16) NOT NULL DEFAULT 'open',
                priority TINYINT UNSIGNED NOT NULL DEFAULT 2,
                created_by INT UNSIGNED NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_due_date (due_date),
                INDEX idx_status (status),
                INDEX idx_created_by (created_by),
                CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by)
                    REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            create_todo_assignments = """
            CREATE TABLE IF NOT EXISTS todo_assignments (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                todo_id INT UNSIGNED NOT NULL,
                assignee_id INT UNSIGNED NOT NULL,
                assignment_status VARCHAR(16) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uk_todo_assignee (todo_id, assignee_id),
                CONSTRAINT fk_ta_todo FOREIGN KEY (todo_id)
                    REFERENCES todos(id) ON DELETE CASCADE,
                CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id)
                    REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            create_sessions = """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(128) PRIMARY KEY,
                employee_id INT UNSIGNED NOT NULL,
                expires_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_emp (employee_id),
                CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_users)
                    cur.execute(create_todos)
                    cur.execute(create_todo_assignments)
                    cur.execute(create_sessions)
                    self._todo_ready = True

                    if lightweight:
                        return

                    for col, ddl in (
                        ('name', "ALTER TABLE users ADD COLUMN name VARCHAR(128) NULL"),
                        ('phone', "ALTER TABLE users ADD COLUMN phone VARCHAR(64) NULL"),
                        ('birthday', "ALTER TABLE users ADD COLUMN birthday DATE NULL"),
                        ('is_admin', "ALTER TABLE users ADD COLUMN is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                        ('can_grant_admin', "ALTER TABLE users ADD COLUMN can_grant_admin TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                        ('page_permissions', "ALTER TABLE users ADD COLUMN page_permissions LONGTEXT NULL"),
                        ('is_approved', "ALTER TABLE users ADD COLUMN is_approved TINYINT(1) NOT NULL DEFAULT 1"),
                    ):
                        cur.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM information_schema.COLUMNS
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'users'
                              AND COLUMN_NAME = %s
                            """,
                            (col,)
                        )
                        row = cur.fetchone()
                        if row and row.get('cnt', 0) == 0:
                            cur.execute(ddl)

                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = 'can_manage_todos'
                        """
                    )
                    can_manage_col = cur.fetchone()
                    if can_manage_col and can_manage_col.get('cnt', 0) > 0:
                        try:
                            cur.execute("ALTER TABLE users DROP COLUMN can_manage_todos")
                        except Exception:
                            pass

                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = 'employee_id'
                        """
                    )
                    emp_col = cur.fetchone()
                    if emp_col and emp_col.get('cnt', 0) > 0:
                        cur.execute(
                            """
                            SELECT CONSTRAINT_NAME
                            FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = 'users'
                              AND COLUMN_NAME = 'employee_id'
                              AND REFERENCED_TABLE_NAME IS NOT NULL
                            """
                        )
                        for fk in cur.fetchall() or []:
                            try:
                                cur.execute(f"ALTER TABLE users DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                            except Exception:
                                pass
                        try:
                            cur.execute("ALTER TABLE users MODIFY COLUMN employee_id INT UNSIGNED NULL")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE users DROP COLUMN employee_id")
                        except Exception:
                            pass

                    for table_name in ('users', 'todos', 'todo_assignments', 'sessions'):
                        cur.execute(
                            """
                            SELECT CONSTRAINT_NAME
                            FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA = DATABASE()
                              AND TABLE_NAME = %s
                              AND REFERENCED_TABLE_NAME = 'employees'
                            """,
                            (table_name,)
                        )
                        for fk in cur.fetchall() or []:
                            try:
                                cur.execute(f"ALTER TABLE {table_name} DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                            except Exception:
                                pass

                    try:
                        cur.execute("DROP TABLE IF EXISTS employees")
                    except Exception:
                        pass

                    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin=1")
                    admin_row = cur.fetchone()
                    if admin_row and admin_row.get('cnt', 0) == 0:
                        cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1")
                        first_user = cur.fetchone()
                        if first_user and first_user.get('id'):
                            cur.execute(
                                "UPDATE users SET is_admin=1, can_grant_admin=1, is_approved=1, page_permissions=%s WHERE id=%s",
                                (self._serialize_page_permissions(self._default_page_permissions()), first_user['id'])
                            )

                    try:
                        cur.execute(
                            "ALTER TABLE todos ADD CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            "ALTER TABLE todo_assignments ADD CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            "ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE"
                        )
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE todo_assignments ADD INDEX idx_ta_assignee_todo (assignee_id, todo_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE todos ADD INDEX idx_todos_creator_due_priority (created_by, due_date, priority, id)")
                    except Exception:
                        pass

            self._todo_schema_migrated = True

    def _split_multi_values(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            raw_items = value
        else:
            raw_items = re.split(r'[\n,，;；/]+', str(value))

        seen = set()
        result = []
        for item in raw_items:
            text = str(item).strip()
            if not text:
                continue
            if text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    def _parse_float(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return float(text)
        except Exception:
            return None

    def _parse_int(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return int(float(text))
        except Exception:
            return None

    def _calc_carton_qty_by_40hq(self, package_length_in, package_width_in, package_height_in):
        length_in = self._parse_float(package_length_in)
        width_in = self._parse_float(package_width_in)
        height_in = self._parse_float(package_height_in)
        if length_in is None or width_in is None or height_in is None:
            return None
        if length_in <= 0 or width_in <= 0 or height_in <= 0:
            return None
        inch_to_meter = 0.0254
        volume_m3 = length_in * inch_to_meter * width_in * inch_to_meter * height_in * inch_to_meter
        if volume_m3 <= 0:
            return None
        qty = int(69.0 / volume_m3)
        return qty if qty >= 0 else None

    def _sanitize_xlsx_bool_cells(self, file_bytes):
        if not file_bytes:
            return file_bytes
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return file_bytes

        out_buffer = io.BytesIO()
        changed = False
        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        valid_bool_values = {'0', '1', 'true', 'false'}

        with zin:
            with zipfile.ZipFile(out_buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    name = info.filename
                    data = zin.read(name)

                    if name.startswith('xl/worksheets/') and name.endswith('.xml'):
                        try:
                            root = ET.fromstring(data)
                            sheet_changed = False
                            for cell in root.findall('.//x:c', ns):
                                if cell.get('t') != 'b':
                                    continue
                                value_node = cell.find('x:v', ns)
                                raw_text = '' if value_node is None or value_node.text is None else str(value_node.text).strip()
                                if raw_text.lower() not in valid_bool_values:
                                    cell.set('t', 'str')
                                    if value_node is None:
                                        value_node = ET.SubElement(cell, '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v')
                                    value_node.text = raw_text
                                    sheet_changed = True
                            if sheet_changed:
                                data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
                                changed = True
                        except Exception:
                            pass

                    zout.writestr(info, data)

        if changed:
            return out_buffer.getvalue()
        return file_bytes

    def _scan_xlsx_invalid_bool_cells(self, file_bytes, max_samples=8):
        if not file_bytes:
            return {'count': 0, 'samples': []}
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return {'count': 0, 'samples': []}

        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        valid_bool_values = {'0', '1', 'true', 'false'}
        count = 0
        samples = []

        with zin:
            for name in zin.namelist():
                if not (name.startswith('xl/worksheets/') and name.endswith('.xml')):
                    continue
                try:
                    root = ET.fromstring(zin.read(name))
                except Exception:
                    continue
                for cell in root.findall('.//x:c', ns):
                    if cell.get('t') != 'b':
                        continue
                    value_node = cell.find('x:v', ns)
                    raw_text = '' if value_node is None or value_node.text is None else str(value_node.text).strip()
                    if raw_text.lower() in valid_bool_values:
                        continue
                    count += 1
                    if len(samples) < max_samples:
                        samples.append({
                            'sheet_xml': name,
                            'cell': cell.get('r') or '',
                            'value': raw_text
                        })

        return {'count': count, 'samples': samples}

    def _xlsx_cell_ref_to_rc(self, ref):
        ref_text = (ref or '').strip().upper()
        match = re.match(r'^([A-Z]+)(\d+)$', ref_text)
        if not match:
            return None, None
        letters, row_text = match.group(1), match.group(2)
        col = 0
        for ch in letters:
            col = col * 26 + (ord(ch) - ord('A') + 1)
        try:
            row = int(row_text)
        except Exception:
            return None, None
        return row, col

    def _extract_xlsx_shared_strings(self, zin):
        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        if 'xl/sharedStrings.xml' not in zin.namelist():
            return []
        try:
            root = ET.fromstring(zin.read('xl/sharedStrings.xml'))
            items = []
            for si in root.findall('.//x:si', ns):
                texts = []
                for t_node in si.findall('.//x:t', ns):
                    texts.append(t_node.text or '')
                items.append(''.join(texts))
            return items
        except Exception:
            return []

    def _rebuild_workbook_from_xlsx_xml(self, file_bytes):
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return None

        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        with zin:
            sheet_names = [name for name in zin.namelist() if name.startswith('xl/worksheets/') and name.endswith('.xml')]
            if not sheet_names:
                return None
            sheet_name = 'xl/worksheets/sheet1.xml' if 'xl/worksheets/sheet1.xml' in sheet_names else sorted(sheet_names)[0]
            try:
                sheet_root = ET.fromstring(zin.read(sheet_name))
            except Exception:
                return None
            shared_strings = self._extract_xlsx_shared_strings(zin)

        wb = Workbook()
        ws = wb.active

        for row_node in sheet_root.findall('.//x:sheetData/x:row', ns):
            row_index = self._parse_int(row_node.get('r')) or 1
            fallback_col = 1
            for cell_node in row_node.findall('x:c', ns):
                ref = cell_node.get('r')
                parsed_row, parsed_col = self._xlsx_cell_ref_to_rc(ref) if ref else (None, None)
                target_row = parsed_row or row_index
                target_col = parsed_col or fallback_col
                fallback_col = target_col + 1

                cell_type = (cell_node.get('t') or '').strip()
                if cell_type == 'inlineStr':
                    text_parts = []
                    for t_node in cell_node.findall('.//x:t', ns):
                        text_parts.append(t_node.text or '')
                    value = ''.join(text_parts)
                else:
                    v_node = cell_node.find('x:v', ns)
                    raw_text = '' if v_node is None or v_node.text is None else str(v_node.text)
                    if cell_type == 's':
                        idx = self._parse_int(raw_text)
                        if idx is not None and 0 <= idx < len(shared_strings):
                            value = shared_strings[idx]
                        else:
                            value = raw_text
                    elif cell_type == 'b':
                        lowered = raw_text.strip().lower()
                        if lowered in ('1', 'true'):
                            value = '1'
                        elif lowered in ('0', 'false'):
                            value = '0'
                        else:
                            value = raw_text
                    else:
                        value = raw_text

                if value != '':
                    ws.cell(row=target_row, column=target_col, value=value)

        return wb

    def _parse_date_str(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            dt = datetime.strptime(text, '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d')
        except Exception:
            return None

    def _normalize_yes_no(self, value):
        text = ('' if value is None else str(value)).strip().lower()
        if text in ('是', 'yes', 'y', 'true', '1'):
            return 1
        if text in ('否', 'no', 'n', 'false', '0'):
            return 0
        return None

    def _normalize_ad_status(self, value):
        text = ('' if value is None else str(value)).strip()
        if text in ('启动', '暂停', '存档'):
            return text
        return None

    def _normalize_observe_interval(self, value):
        text = ('' if value is None else str(value)).strip()
        if not text:
            return None
        return text[:64]

    def _normalize_observe_days(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        m = re.search(r'\d+', text)
        if not m:
            return None
        days = self._parse_int(m.group(0))
        if days is None:
            return None
        if days < 0:
            return None
        return days

    def _normalize_datetime_text(self, value):
        text = ('' if value is None else str(value)).strip()
        if not text:
            return None
        formats = (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M'
        )
        for fmt in formats:
            try:
                dt = datetime.strptime(text, fmt)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                continue
        return None

    def _normalize_bid_value(self, value):
        text = ('' if value is None else str(value)).strip().replace(' ', '')
        if not text:
            return None
        if not re.match(r'^(?:\d+(?:\.\d+)?|\.\d+)%?$', text):
            return None
        is_percent = text.endswith('%')
        num_text = text[:-1] if is_percent else text
        if num_text.startswith('.'):
            num_text = '0' + num_text
        try:
            num = float(num_text)
        except Exception:
            return None
        normalized = ('%.6f' % num).rstrip('0').rstrip('.')
        if normalized == '':
            normalized = '0'
        return normalized + ('%' if is_percent else '')

    def _get_sku_family_with_category_short(self, conn, sku_family_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT pf.id, pf.sku_family, pf.category,
                       pc.category_en AS category_short
                FROM product_families pf
                LEFT JOIN product_categories pc ON pc.category_cn = pf.category
                WHERE pf.id=%s
                """,
                (sku_family_id,)
            )
            return cur.fetchone()

    def _get_ad_item_by_id(self, conn, item_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, ad_level, name, portfolio_id, campaign_id
                FROM amazon_ad_items
                WHERE id=%s
                """,
                (item_id,)
            )
            return cur.fetchone()

    def _build_portfolio_name(self, conn, sku_family_id):
        sku_row = self._get_sku_family_with_category_short(conn, sku_family_id)
        if not sku_row:
            return None
        short = (sku_row.get('category_short') or sku_row.get('category') or '').strip()
        sku_family = (sku_row.get('sku_family') or '').strip()
        if not short or not sku_family:
            return None
        return f"{short}-{sku_family}"

    def _build_campaign_name(self, conn, strategy_code, portfolio_id, subtype_id):
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM amazon_ad_items WHERE id=%s AND ad_level='portfolio'", (portfolio_id,))
            portfolio = cur.fetchone()
            if not portfolio:
                return None
            cur.execute("SELECT id, ad_class, subtype_code FROM amazon_ad_subtypes WHERE id=%s", (subtype_id,))
            subtype = cur.fetchone()
            if not subtype:
                return None
        strategy = (strategy_code or '').strip().upper()
        if strategy not in ('BE', 'BD', 'PC'):
            return None
        return f"{strategy}-{portfolio.get('name') or ''}-{subtype.get('ad_class') or ''}-{subtype.get('subtype_code') or ''}"

    def _get_material_type_id(self, conn, name_or_code):
        if not name_or_code:
            return None
        type_map = {
            'fabric': '面料',
            'filling': '填充',
            'frame': '框架',
            'electronics': '电子元器件'
        }
        name = type_map.get(name_or_code, name_or_code)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM material_types WHERE name=%s", (name,))
            row = cur.fetchone()
            return row['id'] if row else None

    def _materials_has_type_id(self, conn):
        with conn.cursor() as cur:
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
            return bool(row and row.get('cnt', 0) > 0)

    def _materials_has_parent_id(self, conn):
        with conn.cursor() as cur:
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
            return bool(row and row.get('cnt', 0) > 0)

    def _upsert_material_ids(self, conn, names, material_type_code):
        ids = []
        if not names:
            return ids
        with conn.cursor() as cur:
            material_type_id = self._get_material_type_id(conn, material_type_code)
            if not material_type_id:
                return ids
            for name in names:
                cur.execute(
                    "SELECT id FROM materials WHERE material_type_id=%s AND name=%s",
                    (material_type_id, name)
                )
                row = cur.fetchone()
                if row:
                    ids.append(row['id'])
                    continue
                cur.execute(
                    "INSERT INTO materials (name, material_type_id) VALUES (%s, %s)",
                    (name, material_type_id)
                )
                ids.append(cur.lastrowid)
        return ids

    def _upsert_feature_ids(self, conn, names):
        ids = []
        if not names:
            return ids
        with conn.cursor() as cur:
            for name in names:
                cur.execute("SELECT id FROM features WHERE name=%s", (name,))
                row = cur.fetchone()
                if row:
                    ids.append(row['id'])
                    continue
                cur.execute("INSERT INTO features (name) VALUES (%s)", (name,))
                ids.append(cur.lastrowid)
        return ids

    def _replace_order_product_materials(self, conn, order_product_id, filling_names, frame_names):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_materials WHERE order_product_id=%s", (order_product_id,))

        for material_type, names in (
            ('filling', filling_names),
            ('frame', frame_names)
        ):
            ids = self._upsert_material_ids(conn, names, material_type)
            if not ids:
                continue
            with conn.cursor() as cur:
                for material_id in ids:
                    cur.execute(
                        "INSERT IGNORE INTO order_product_materials (order_product_id, material_id) VALUES (%s, %s)",
                        (order_product_id, material_id)
                    )

    def _replace_order_product_features(self, conn, order_product_id, feature_names):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_features WHERE order_product_id=%s", (order_product_id,))

        feature_ids = self._upsert_feature_ids(conn, feature_names)
        if not feature_ids:
            return
        with conn.cursor() as cur:
            for feature_id in feature_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_features (order_product_id, feature_id) VALUES (%s, %s)",
                    (order_product_id, feature_id)
                )

    def _replace_order_product_material_ids(self, conn, order_product_id, filling_ids, frame_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_materials WHERE order_product_id=%s", (order_product_id,))

        material_ids = []
        if filling_ids:
            material_ids.extend(filling_ids)
        if frame_ids:
            material_ids.extend(frame_ids)
        if not material_ids:
            return
        material_ids = sorted(set(material_ids))
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT IGNORE INTO order_product_materials (order_product_id, material_id) VALUES (%s, %s)",
                [(order_product_id, material_id) for material_id in material_ids]
            )

    def _replace_order_product_feature_ids(self, conn, order_product_id, feature_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_features WHERE order_product_id=%s", (order_product_id,))

        if not feature_ids:
            return
        feature_ids = sorted(set(feature_ids))
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT IGNORE INTO order_product_features (order_product_id, feature_id) VALUES (%s, %s)",
                [(order_product_id, feature_id) for feature_id in feature_ids]
            )

    def _replace_order_product_certification_ids(self, conn, order_product_id, certification_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_certifications WHERE order_product_id=%s", (order_product_id,))

        if not certification_ids:
            return
        certification_ids = sorted(set(certification_ids))
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT IGNORE INTO order_product_certifications (order_product_id, certification_id) VALUES (%s, %s)",
                [(order_product_id, certification_id) for certification_id in certification_ids]
            )

    def _replace_feature_categories(self, conn, feature_id, category_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM feature_categories WHERE feature_id=%s", (feature_id,))

        if not category_ids:
            return
        with conn.cursor() as cur:
            for category_id in category_ids:
                cur.execute(
                    "INSERT IGNORE INTO feature_categories (feature_id, category_id) VALUES (%s, %s)",
                    (feature_id, category_id)
                )

    def _replace_fabric_sku_family_ids(self, conn, fabric_id, sku_family_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE fabric_id=%s", (fabric_id,))

        if not sku_family_ids:
            return
        with conn.cursor() as cur:
            for sku_family_id in sku_family_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def _replace_sku_family_fabric_ids(self, conn, sku_family_id, fabric_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE sku_family_id=%s", (sku_family_id,))

        if not fabric_ids:
            return
        with conn.cursor() as cur:
            for fabric_id in fabric_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def _replace_ad_subtype_operation_type_ids(self, conn, subtype_id, operation_type_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM amazon_ad_subtype_operation_types WHERE subtype_id=%s", (subtype_id,))

        if not operation_type_ids:
            return
        with conn.cursor() as cur:
            rows = []
            seen = set()
            for operation_type_id in operation_type_ids:
                op_id = self._parse_int(operation_type_id)
                if not op_id or op_id in seen:
                    continue
                seen.add(op_id)
                rows.append((subtype_id, op_id))
            if rows:
                cur.executemany(
                    "INSERT IGNORE INTO amazon_ad_subtype_operation_types (subtype_id, operation_type_id) VALUES (%s, %s)",
                    rows
                )

    def _normalize_ad_operation_reasons(self, reasons):
        items = []
        seen = set()
        if not isinstance(reasons, list):
            return items
        for entry in reasons:
            reason_name = ''
            if isinstance(entry, dict):
                reason_name = (entry.get('reason_name') or entry.get('name') or '').strip()
            elif entry is not None:
                reason_name = str(entry).strip()
            if not reason_name:
                continue
            norm = reason_name.lower()
            if norm in seen:
                continue
            seen.add(norm)
            items.append({'reason_name': reason_name})
        return items

    def _replace_ad_operation_type_reasons(self, conn, operation_type_id, reasons):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM amazon_ad_operation_reasons WHERE operation_type_id=%s", (operation_type_id,))

        if not reasons:
            return
        with conn.cursor() as cur:
            rows = []
            seen = set()
            for reason in reasons:
                reason_name = (reason.get('reason_name') or '').strip()
                if not reason_name:
                    continue
                key = reason_name.lower()
                if key in seen:
                    continue
                seen.add(key)
                rows.append((operation_type_id, reason_name))
            if rows:
                cur.executemany(
                    "INSERT IGNORE INTO amazon_ad_operation_reasons (operation_type_id, reason_name) VALUES (%s, %s)",
                    rows
                )

    def _normalize_sales_order_links(self, links):
        items = []
        if not isinstance(links, list):
            return items
        for entry in links:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not order_product_id:
                continue
            items.append({'order_product_id': order_product_id, 'quantity': max(1, quantity)})
        return items

    def _normalize_shipping_plan_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for idx, entry in enumerate(items, start=1):
            if not isinstance(entry, dict):
                continue
            substitute_order_product_id = self._parse_int(entry.get('substitute_order_product_id') or entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not substitute_order_product_id:
                continue
            normalized.append({
                'substitute_order_product_id': substitute_order_product_id,
                'quantity': max(1, quantity),
                'sort_order': self._parse_int(entry.get('sort_order')) or idx
            })
        return normalized

    def _has_duplicate_shipping_plan_substitutes(self, items):
        seen = set()
        for item in (items or []):
            sid = self._parse_int(item.get('substitute_order_product_id'))
            if not sid:
                continue
            if sid in seen:
                return True
            seen.add(sid)
        return False

    def _replace_shipping_plan_items(self, conn, plan_id, items):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_shipping_plan_items WHERE shipping_plan_id=%s", (plan_id,))
            if not items:
                return
            rows = [
                (plan_id, item['substitute_order_product_id'], item['quantity'], item['sort_order'])
                for item in items
            ]
            cur.executemany(
                """
                INSERT INTO order_product_shipping_plan_items
                    (shipping_plan_id, substitute_order_product_id, quantity, sort_order)
                VALUES (%s, %s, %s, %s)
                """,
                rows
            )

    def _ensure_default_iteration_shipping_plans(self, conn, order_product_id):
        target_id = self._parse_int(order_product_id)
        if not target_id:
            return
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM order_product_shipping_plans WHERE order_product_id=%s", (target_id,))
            row = cur.fetchone() or {}
            if int(row.get('cnt') or 0) > 0:
                return

            cur.execute(
                """
                SELECT id, source_order_product_id, version_no, is_iteration
                FROM order_products
                WHERE id=%s
                """,
                (target_id,)
            )
            current = cur.fetchone() or {}
            if int(current.get('is_iteration') or 0) != 1:
                return
            source_id = self._parse_int(current.get('source_order_product_id'))
            if not source_id:
                return

            version_text = str(current.get('version_no') or '').strip()
            plan_name = f"迭代款-{version_text}" if version_text else "迭代款-1"

            cur.execute(
                """
                SELECT id
                FROM order_products
                WHERE (id=%s OR source_order_product_id=%s)
                  AND id<>%s
                  AND is_on_market=1
                ORDER BY CAST(NULLIF(version_no, '') AS UNSIGNED) ASC, id ASC
                """,
                (source_id, source_id, target_id)
            )
            siblings = cur.fetchall() or []

            candidate_ids = []
            for sibling in siblings:
                sibling_id = self._parse_int(sibling.get('id'))
                if sibling_id and sibling_id not in candidate_ids:
                    candidate_ids.append(sibling_id)

            if not candidate_ids:
                return

            cur.execute(
                """
                INSERT INTO order_product_shipping_plans (order_product_id, plan_name)
                VALUES (%s, %s)
                """,
                (target_id, plan_name)
            )
            plan_id = cur.lastrowid
            rows = []
            for idx, substitute_id in enumerate(candidate_ids, start=1):
                rows.append((plan_id, substitute_id, 1, idx))
            cur.executemany(
                """
                INSERT INTO order_product_shipping_plan_items
                    (shipping_plan_id, substitute_order_product_id, quantity, sort_order)
                VALUES (%s, %s, %s, %s)
                """,
                rows
            )

    def _bool_from_any(self, value, default=0):
        if value is None:
            return 1 if default else 0
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'y', '是', 'on'):
            return 1
        if text in ('0', 'false', 'no', 'n', '否', 'off'):
            return 0
        return 1 if default else 0

    def _validate_us_phone_zip(self, phone, zip_code):
        phone_text = (phone or '').strip()
        zip_text = (zip_code or '').strip()
        if phone_text:
            digits = re.sub(r'\D+', '', phone_text)
            if len(digits) == 11 and digits.startswith('1'):
                digits = digits[1:]
            if len(digits) != 10:
                raise ValueError('电话格式无效，请填写美国电话（10位数字，可含+1）')
        if zip_text and not re.match(r'^\d{5}(-\d{4})?$', zip_text):
            raise ValueError('邮编格式无效，请填写美国邮编（5位或5+4）')

    def _normalize_registration_platform_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for entry in items:
            if not isinstance(entry, dict):
                continue
            platform_sku = (entry.get('platform_sku') or '').strip()
            sales_product_id = self._parse_int(entry.get('sales_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            shipping_plan_id = self._parse_int(entry.get('shipping_plan_id'))
            if not platform_sku and not sales_product_id:
                continue
            normalized.append({
                'sales_product_id': sales_product_id,
                'platform_sku': platform_sku,
                'quantity': max(1, quantity),
                'shipping_plan_id': shipping_plan_id
            })
        return normalized

    def _normalize_registration_shipment_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for entry in items:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            order_sku = (entry.get('order_sku') or '').strip()
            quantity = self._parse_int(entry.get('quantity')) or 1
            shipping_plan_id = self._parse_int(entry.get('shipping_plan_id'))
            source_type = (entry.get('source_type') or 'manual').strip().lower()
            if source_type not in ('manual', 'auto', 'plan'):
                source_type = 'manual'
            if not order_product_id and not order_sku:
                continue
            normalized.append({
                'order_product_id': order_product_id,
                'order_sku': order_sku,
                'quantity': max(1, quantity),
                'source_type': source_type,
                'shipping_plan_id': shipping_plan_id
            })
        return normalized

    def _normalize_registration_logistics_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for index, entry in enumerate(items, start=1):
            if not isinstance(entry, dict):
                continue
            shipping_carrier = (entry.get('shipping_carrier') or '').strip()
            tracking_no = (entry.get('tracking_no') or '').strip()
            sort_order = self._parse_int(entry.get('sort_order')) or index
            if not shipping_carrier and not tracking_no:
                continue
            normalized.append({
                'shipping_carrier': shipping_carrier or None,
                'tracking_no': tracking_no or None,
                'sort_order': max(1, sort_order)
            })
        return normalized

    def _resolve_registration_auto_shipments(self, conn, platform_items):
        aggregate = {}
        if not platform_items:
            return []

        with conn.cursor() as cur:
            for item in platform_items:
                qty = max(1, self._parse_int(item.get('quantity')) or 1)
                shipping_plan_id = self._parse_int(item.get('shipping_plan_id'))

                if shipping_plan_id:
                    cur.execute(
                        """
                        SELECT op.id AS order_product_id, op.sku, opsi.quantity
                        FROM order_product_shipping_plan_items opsi
                        JOIN order_products op ON op.id = opsi.substitute_order_product_id
                        WHERE opsi.shipping_plan_id=%s
                        ORDER BY opsi.sort_order ASC, opsi.id ASC
                        """,
                        (shipping_plan_id,)
                    )
                    rels = cur.fetchall() or []
                    for rel in rels:
                        key = int(rel.get('order_product_id'))
                        aggregate.setdefault(key, {
                            'order_product_id': key,
                            'order_sku': rel.get('sku') or '',
                            'quantity': 0,
                            'source_type': 'plan',
                            'shipping_plan_id': shipping_plan_id
                        })
                        aggregate[key]['quantity'] += qty * (self._parse_int(rel.get('quantity')) or 1)
                    continue

                sales_product_id = self._parse_int(item.get('sales_product_id'))
                platform_sku = (item.get('platform_sku') or '').strip()
                if not sales_product_id and platform_sku:
                    cur.execute("SELECT id FROM sales_products WHERE platform_sku=%s LIMIT 1", (platform_sku,))
                    row = cur.fetchone() or {}
                    sales_product_id = self._parse_int(row.get('id'))
                if not sales_product_id:
                    continue

                cur.execute(
                    """
                    SELECT op.id AS order_product_id, op.sku, spol.quantity
                    FROM sales_product_order_links spol
                    JOIN order_products op ON op.id = spol.order_product_id
                    WHERE spol.sales_product_id=%s
                    """,
                    (sales_product_id,)
                )
                rels = cur.fetchall() or []
                for rel in rels:
                    key = int(rel.get('order_product_id'))
                    aggregate.setdefault(key, {
                        'order_product_id': key,
                        'order_sku': rel.get('sku') or '',
                        'quantity': 0,
                        'source_type': 'auto',
                        'shipping_plan_id': None
                    })
                    aggregate[key]['quantity'] += qty * (self._parse_int(rel.get('quantity')) or 1)

        items = list(aggregate.values())
        items.sort(key=lambda x: (x.get('order_sku') or '', x.get('order_product_id') or 0))
        return items

    def _normalize_keyword_tag_names(self, value):
        if value is None:
            return []
        raw_items = []
        if isinstance(value, list):
            raw_items = value
        else:
            raw_items = re.split(r'[\n\r;,；]+', str(value))
        seen = set()
        result = []
        for item in raw_items:
            name = ('' if item is None else str(item)).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(name[:64])
        return result

    def _normalize_keyword_sku_ids(self, value):
        items = []
        if value is None:
            return items
        if isinstance(value, list):
            raw = value
        else:
            raw = re.split(r'[\n\r,;；]+', str(value))
        for entry in raw:
            sku_id = self._parse_int(entry)
            if sku_id:
                items.append(sku_id)
        return sorted(set(items))

    def _ensure_keyword_tags(self, conn, category_id, tag_names):
        if not tag_names:
            return []
        with conn.cursor() as cur:
            for name in tag_names:
                cur.execute(
                    """
                    INSERT INTO amazon_keyword_tags (category_id, tag_name)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE tag_name=VALUES(tag_name)
                    """,
                    (category_id, name)
                )
            placeholders = ','.join(['%s'] * len(tag_names))
            cur.execute(
                f"""
                SELECT id, tag_name
                FROM amazon_keyword_tags
                WHERE category_id=%s
                  AND tag_name IN ({placeholders})
                """,
                [category_id] + tag_names
            )
            rows = cur.fetchall() or []
        name_to_id = {str(row.get('tag_name')): int(row.get('id')) for row in rows if row.get('id')}
        return [name_to_id[name] for name in tag_names if name in name_to_id]

    def _replace_keyword_tags(self, conn, keyword_id, category_id, tag_names):
        tag_ids = self._ensure_keyword_tags(conn, category_id, tag_names)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM amazon_keyword_tag_rel WHERE keyword_id=%s", (keyword_id,))
            if tag_ids:
                cur.executemany(
                    "INSERT IGNORE INTO amazon_keyword_tag_rel (keyword_id, tag_id) VALUES (%s, %s)",
                    [(keyword_id, tag_id) for tag_id in tag_ids]
                )

    def _replace_keyword_sku_relevance(self, conn, keyword_id, sku_family_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM amazon_keyword_sku_rel WHERE keyword_id=%s", (keyword_id,))
            if sku_family_ids:
                cur.executemany(
                    """
                    INSERT INTO amazon_keyword_sku_rel (keyword_id, sku_family_id, relevance_score)
                    VALUES (%s, %s, 1)
                    """,
                    [(keyword_id, sku_id) for sku_id in sku_family_ids]
                )

    def _replace_sales_order_links(self, conn, sales_product_id, links):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sales_product_order_links WHERE sales_product_id=%s", (sales_product_id,))
        if not links:
            return
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO sales_product_order_links (sales_product_id, order_product_id, quantity)
                VALUES (%s, %s, %s)
                """,
                [(sales_product_id, entry['order_product_id'], entry['quantity']) for entry in links]
            )

    def _derive_sales_fields(self, conn, sku_family_id, links):
        """自动推导销售产品的面料、规格名称和平台SKU"""
        if not links:
            return '', '', ''
        
        # 获取货号系列代码
        sku_family_code = ''
        if sku_family_id:
            with conn.cursor() as cur:
                cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                row = cur.fetchone()
                if row:
                    sku_family_code = (row.get('sku_family') or '').strip()
        
        # 获取下单产品信息
        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT op.id, op.sku, op.spec_qty_short, fm.fabric_code, fm.fabric_name_en
                FROM order_products op
                LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                WHERE op.id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []
        
        row_map = {row['id']: row for row in rows}
        fabrics = []
        spec_parts = []
        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            fabric_code = self._code_before_dash(row.get('fabric_code'))
            if not fabric_code:
                fabric_code = self._code_before_dash(row.get('fabric_name_en'))
            if fabric_code and fabric_code not in fabrics:
                fabrics.append(fabric_code)
            spec_short = (row.get('spec_qty_short') or '').strip()
            if spec_short:
                spec_parts.append(f"{entry['quantity']}{spec_short}")
        
        fabric = ' / '.join(fabrics)
        spec_name = ''.join(spec_parts)
        
        # 自动生成平台SKU: 货号-规格名称-面料编号
        platform_sku = ''
        if sku_family_code and fabric and spec_name:
            first_fabric = fabrics[0] if fabrics else ''
            platform_sku = self._build_sales_platform_sku(sku_family_code, spec_name, first_fabric)
        
        return fabric, spec_name, platform_sku

    def _derive_sales_cost_size(self, conn, links):
        """根据关联下单SKU推导成本与尺寸重量（包裹长宽高取最大值）"""
        if not links:
            return {
                'warehouse_cost_usd': 0.0,
                'last_mile_cost_usd': 0.0,
                'package_length_in': 0.0,
                'package_width_in': 0.0,
                'package_height_in': 0.0,
                'net_weight_lbs': 0.0,
                'gross_weight_lbs': 0.0,
                'sku_family_id': None
            }

        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, sku_family_id,
                       cost_usd, last_mile_avg_freight_usd,
                       package_length_in, package_width_in, package_height_in,
                       net_weight_lbs, gross_weight_lbs
                FROM order_products
                WHERE id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []

        row_map = {row['id']: row for row in rows}
        warehouse_cost_usd = 0.0
        last_mile_cost_usd = 0.0
        package_length_in = 0.0
        package_width_in = 0.0
        package_height_in = 0.0
        net_weight_lbs = 0.0
        gross_weight_lbs = 0.0
        sku_family_id = None

        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            qty = max(1, int(entry.get('quantity') or 1))
            if sku_family_id is None:
                sku_family_id = row.get('sku_family_id')

            warehouse_cost_usd += float(row.get('cost_usd') or 0) * qty
            last_mile_cost_usd += float(row.get('last_mile_avg_freight_usd') or 0) * qty
            package_length_in = max(package_length_in, float(row.get('package_length_in') or 0))
            package_width_in = max(package_width_in, float(row.get('package_width_in') or 0))
            package_height_in = max(package_height_in, float(row.get('package_height_in') or 0))
            net_weight_lbs += float(row.get('net_weight_lbs') or 0) * qty
            gross_weight_lbs += float(row.get('gross_weight_lbs') or 0) * qty

        return {
            'warehouse_cost_usd': round(warehouse_cost_usd, 2),
            'last_mile_cost_usd': round(last_mile_cost_usd, 2),
            'package_length_in': round(package_length_in, 2),
            'package_width_in': round(package_width_in, 2),
            'package_height_in': round(package_height_in, 2),
            'net_weight_lbs': round(net_weight_lbs, 2),
            'gross_weight_lbs': round(gross_weight_lbs, 2),
            'sku_family_id': sku_family_id
        }

    def _get_fabric_folder_bytes(self):
        return self._join_resources('『面料』')

    def _ensure_fabric_folder(self):
        folder = self._get_fabric_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _get_listing_folder_bytes(self):
        # RESOURCES_PATH_BYTES already points to the decoded child (上架资源),
        # so listing folder is the resources path itself.
        return RESOURCES_PATH_BYTES

    def _ensure_listing_folder(self):
        folder = self._get_listing_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _ensure_listing_sku_folder(self, sku_family):
        if not sku_family:
            return
        base_folder = self._ensure_listing_folder()
        try:
            sku_bytes = os.fsencode(sku_family)
        except Exception:
            sku_bytes = str(sku_family).encode('utf-8', errors='surrogatepass')
        target = os.path.join(base_folder, sku_bytes)
        if not os.path.exists(target):
            os.makedirs(target, exist_ok=True)
        # Create standard subfolders for the SKU
        for sub in ('源文件', '主图', 'A+', '关联文件', '视频', '上传模板'):
            try:
                sub_bytes = os.fsencode(sub)
            except Exception:
                sub_bytes = str(sub).encode('utf-8', errors='surrogatepass')
            sub_path = os.path.join(target, sub_bytes)
            if not os.path.exists(sub_path):
                os.makedirs(sub_path, exist_ok=True)

        # Ensure default common folders under 主图 and A+
        for parent_sub in ('主图', 'A+'):
            try:
                parent_sub_bytes = os.fsencode(parent_sub)
            except Exception:
                parent_sub_bytes = str(parent_sub).encode('utf-8', errors='surrogatepass')
            parent_path = os.path.join(target, parent_sub_bytes)
            try:
                common_sub_bytes = os.fsencode('通用')
            except Exception:
                common_sub_bytes = '通用'.encode('utf-8', errors='surrogatepass')
            common_path = os.path.join(parent_path, common_sub_bytes)
            if not os.path.exists(common_path):
                os.makedirs(common_path, exist_ok=True)

    def _rename_listing_sku_folder(self, old_sku_family, new_sku_family):
        old_name = (old_sku_family or '').strip()
        new_name = (new_sku_family or '').strip()
        if (not old_name) or (not new_name) or old_name == new_name:
            return {'status': 'success', 'renamed': False}

        base_folder = self._ensure_listing_folder()
        old_path = os.path.join(base_folder, self._safe_fsencode(old_name))
        new_path = os.path.join(base_folder, self._safe_fsencode(new_name))

        if not os.path.exists(old_path):
            # 旧目录不存在时按新名称补齐目录
            self._ensure_listing_sku_folder(new_name)
            return {'status': 'success', 'renamed': False}

        if os.path.exists(new_path):
            return {'status': 'error', 'message': f'目标目录已存在: {new_name}'}

        try:
            os.rename(old_path, new_path)
            return {'status': 'success', 'renamed': True}
        except Exception as e:
            return {'status': 'error', 'message': f'重命名目录失败: {e}'}

    def _code_before_dash(self, value):
        text = (value or '').strip()
        if not text:
            return ''
        return text.split('-', 1)[0].strip() or text

    def _build_sales_platform_sku(self, sku_family_code, spec_name, fabric_code):
        sku_part = (sku_family_code or '').strip()
        spec_part = (spec_name or '').strip()
        fabric_part = self._code_before_dash(fabric_code)
        if not (sku_part and spec_part and fabric_part):
            return ''
        return f"{sku_part}-{spec_part}-{fabric_part}"

    def _ensure_listing_sales_variant_folder(self, sku_family, spec_name, fabric_code):
        sku_name = (sku_family or '').strip()
        if not sku_name:
            return
        self._ensure_listing_sku_folder(sku_name)
        base_folder = self._ensure_listing_folder()
        sku_folder = os.path.join(base_folder, self._safe_fsencode(sku_name))
        main_folder = os.path.join(sku_folder, self._safe_fsencode('主图'))
        if not os.path.exists(main_folder):
            os.makedirs(main_folder, exist_ok=True)

        spec_part = (spec_name or '').strip().replace('/', '-').replace('\\', '-')
        fabric_part = self._code_before_dash(fabric_code).replace('/', '-').replace('\\', '-')
        if not (spec_part and fabric_part):
            return
        variant_folder_name = f"{spec_part}-{fabric_part}"
        variant_folder = os.path.join(main_folder, self._safe_fsencode(variant_folder_name))
        if not os.path.exists(variant_folder):
            os.makedirs(variant_folder, exist_ok=True)

    def _get_certification_folder_bytes(self):
        return self._join_resources('『认证』')

    def _ensure_certification_folder(self):
        folder = self._get_certification_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _normalize_fabric_image_names(self, image_names):
        if not image_names:
            return []
        if isinstance(image_names, (str, bytes, bytearray)):
            raw = [image_names]
        else:
            raw = list(image_names)
        seen = set()
        result = []
        for name in raw:
            if isinstance(name, (bytes, bytearray)):
                try:
                    name = os.fsdecode(name)
                except Exception:
                    name = name.decode('utf-8', errors='ignore')
            name = (str(name).strip() if name is not None else '')
            if not name or name in seen:
                continue
            seen.add(name)
            result.append(name)
        return result

    def _parse_fabric_images_payload(self, images_data):
        """解析图片数组数据，支持新旧格式
        新格式: [{'image_name': 'xxx', 'remark': '原图/卖点图', 'sort_order': 0}, ...]
        旧格式: ['image_name1', 'image_name2', ...]
        返回: [{'image_name': str, 'remark': str|None, 'sort_order': int, 'is_primary': bool}, ...]
        """
        if not images_data:
            return []
        
        result = []
        if isinstance(images_data, list):
            for idx, item in enumerate(images_data):
                if isinstance(item, dict):
                    # 新格式
                    result.append({
                        'image_name': (item.get('image_name') or '').strip(),
                        'remark': self._normalize_fabric_remark(item.get('remark')),
                        'sort_order': self._parse_int(item.get('sort_order')) or idx,
                        'is_primary': bool(item.get('is_primary', idx == 0))
                    })
                else:
                    # 旧格式字符串
                    result.append({
                        'image_name': str(item).strip(),
                        'remark': '原图',
                        'sort_order': idx,
                        'is_primary': (idx == 0)
                    })
        return [r for r in result if r['image_name']]
    
    def _rename_fabric_image_with_remark(self, old_name, fabric_code, remark, index):
        """根据新命名规则重命名图片: 面料编号-备注-序号
        Args:
            old_name: 原文件名
            fabric_code: 面料编号
            remark: 备注类型（原图/卖点图）
            index: 在该备注类型下的序号（从1开始）
        Returns:
            新文件名，如果文件名已符合规则且序号正确则返回原文件名
        """
        if not old_name:
            return None
        
        ext = os.path.splitext(old_name)[1] or '.jpg'
        remark_str = remark or '未分类'
        new_name = f"{fabric_code}-{remark_str}-{index:02d}{ext}"
        
        # 如果原文件名已经符合新规则，保持不变
        if old_name == new_name:
            return old_name
        
        return new_name

    def _next_fabric_image_index(self, existing_names, fabric_code):
        max_idx = 0
        prefix = f"{fabric_code}_"
        for name in existing_names:
            if not name:
                continue
            if name.startswith(prefix):
                match = re.match(rf"^{re.escape(prefix)}(\\d+)", name)
                if match:
                    try:
                        max_idx = max(max_idx, int(match.group(1)))
                    except Exception:
                        continue
            elif name.startswith(f"{fabric_code}."):
                max_idx = max(max_idx, 1)
        return max_idx + 1

    def _build_fabric_upload_name(self, fabric_code, filename, existing_names):
        ext = os.path.splitext(filename)[1]
        index = self._next_fabric_image_index(existing_names, fabric_code)
        return f"{fabric_code}_{index:02d}{ext}"



    def handle_certification_images_api(self, environ, start_response):
        """列出认证文件夹内图片"""
        try:
            folder = self._ensure_certification_folder()

            items = []
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        raw = entry.name
                        if isinstance(raw, str):
                            try:
                                raw_bytes = os.fsencode(raw)
                            except Exception:
                                raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                        else:
                            raw_bytes = bytes(raw)

                        try:
                            name = os.fsdecode(raw_bytes)
                            name = name.encode('utf-8', errors='surrogatepass').decode('utf-8', errors='replace')
                        except Exception:
                            name = raw_bytes.decode('utf-8', errors='replace')

                        try:
                            folder_bytes = os.fsencode('『认证』')
                        except Exception:
                            folder_bytes = '『认证』'.encode('utf-8', errors='surrogatepass')
                        rel_bytes = os.path.join(folder_bytes, raw_bytes)
                        items.append({
                            'name': name,
                            'name_raw_b64': base64.b64encode(raw_bytes).decode('ascii'),
                            'b64': base64.b64encode(rel_bytes).decode('ascii')
                        })

            try:
                items.sort(key=lambda x: (x.get('name') or '').lower())
            except Exception:
                pass
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)




    def handle_amazon_account_health_api(self, environ, method, start_response):
        """Amazon 账户健康管理 API（CRUD + 图表）"""
        try:
            self._ensure_amazon_account_health_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            int_fields = [
                'account_health_rating',
                'suspected_ip_infringement',
                'intellectual_property_complaints',
                'authenticity_customer_complaints',
                'condition_customer_complaints',
                'food_safety_issues',
                'listing_policy_violations',
                'restricted_product_policy_violations',
                'customer_review_policy_violations',
                'other_policy_violations',
                'regulatory_compliance_issues'
            ]
            percent_fields = [
                'order_defect_rate',
                'negative_feedback_rate',
                'a_to_z_rate',
                'chargeback_rate',
                'late_shipment_rate',
                'pre_fulfillment_cancel_rate',
                'valid_tracking_rate',
                'on_time_delivery_rate'
            ]

            if method == 'GET':
                mode = (query_params.get('mode', [''])[0] or '').strip().lower()
                keyword = (query_params.get('q', [''])[0] or '').strip()
                shop_id = self._parse_int((query_params.get('shop_id', [''])[0] or '').strip())
                start_date = self._parse_date_str((query_params.get('start_date', [''])[0] or '').strip())
                end_date = self._parse_date_str((query_params.get('end_date', [''])[0] or '').strip())

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id FROM platform_types
                            WHERE LOWER(TRIM(name))='amazon'
                            ORDER BY id ASC
                            LIMIT 1
                            """
                        )
                        amazon_platform = cur.fetchone() or {}
                        amazon_platform_id = amazon_platform.get('id')
                        if not amazon_platform_id:
                            return self.send_json({'status': 'success', 'items': []}, start_response)

                        if mode == 'chart':
                            if not shop_id:
                                return self.send_json({'status': 'error', 'message': 'Missing shop_id'}, start_response)
                            cur.execute(
                                "SELECT id FROM shops WHERE id=%s AND platform_type_id=%s",
                                (shop_id, amazon_platform_id)
                            )
                            selected_shop = cur.fetchone()
                            if not selected_shop:
                                return self.send_json({'status': 'error', 'message': 'Shop is not Amazon platform'}, start_response)
                            sql = [
                                """
                                SELECT DATE(a.record_datetime) AS record_date,
                                       ROUND(AVG(a.account_health_rating), 2) AS account_health_rating,
                                       ROUND(AVG(a.order_defect_rate), 4) AS order_defect_rate,
                                       ROUND(AVG(a.late_shipment_rate), 4) AS late_shipment_rate,
                                       ROUND(AVG(a.pre_fulfillment_cancel_rate), 4) AS pre_fulfillment_cancel_rate,
                                       ROUND(AVG(a.valid_tracking_rate), 4) AS valid_tracking_rate,
                                       ROUND(AVG(a.on_time_delivery_rate), 4) AS on_time_delivery_rate
                                FROM amazon_account_health a
                                LEFT JOIN shops s ON s.id = a.shop_id
                                WHERE a.shop_id=%s AND s.platform_type_id=%s
                                """
                            ]
                            params = [shop_id, amazon_platform_id]
                            if start_date:
                                sql.append("AND DATE(a.record_datetime) >= %s")
                                params.append(start_date)
                            if end_date:
                                sql.append("AND DATE(a.record_datetime) <= %s")
                                params.append(end_date)
                            sql.append("GROUP BY DATE(a.record_datetime) ORDER BY DATE(a.record_datetime) ASC")
                            cur.execute("\n".join(sql), params)
                            rows = cur.fetchall()
                            return self.send_json({'status': 'success', 'items': rows}, start_response)

                        sql = [
                            """
                            SELECT a.*, s.shop_name
                            FROM amazon_account_health a
                            LEFT JOIN shops s ON s.id = a.shop_id
                            WHERE s.platform_type_id=%s
                            """
                        ]
                        params = [amazon_platform_id]
                        if shop_id:
                            sql.append("AND a.shop_id=%s")
                            params.append(shop_id)
                        if start_date:
                            sql.append("AND DATE(a.record_datetime) >= %s")
                            params.append(start_date)
                        if end_date:
                            sql.append("AND DATE(a.record_datetime) <= %s")
                            params.append(end_date)
                        if keyword:
                            sql.append("AND (s.shop_name LIKE %s OR a.remark LIKE %s)")
                            params.extend([f"%{keyword}%", f"%{keyword}%"])
                        sql.append("ORDER BY a.record_datetime DESC, a.id DESC")
                        cur.execute("\n".join(sql), params)
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                shop_id = self._parse_int(data.get('shop_id'))
                if not shop_id:
                    return self.send_json({'status': 'error', 'message': 'Missing shop_id'}, start_response)

                values = {}
                for key in int_fields:
                    parsed = self._parse_int(data.get(key))
                    if parsed is None:
                        return self.send_json({'status': 'error', 'message': f'Missing or invalid {key}'}, start_response)
                    values[key] = parsed
                for key in percent_fields:
                    parsed = self._parse_float(data.get(key))
                    if parsed is None:
                        return self.send_json({'status': 'error', 'message': f'Missing or invalid {key}'}, start_response)
                    values[key] = parsed

                record_datetime = self._normalize_datetime_text(data.get('record_datetime')) or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                remark = (data.get('remark') or '').strip()[:500]

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT s.id
                            FROM shops s
                            JOIN platform_types pt ON pt.id = s.platform_type_id
                            WHERE s.id=%s AND LOWER(TRIM(pt.name))='amazon'
                            """,
                            (shop_id,)
                        )
                        allowed_shop = cur.fetchone()
                        if not allowed_shop:
                            return self.send_json({'status': 'error', 'message': 'Only Amazon platform shop is allowed'}, start_response)
                        cur.execute(
                            """
                            INSERT INTO amazon_account_health (
                                shop_id, account_health_rating,
                                suspected_ip_infringement, intellectual_property_complaints,
                                authenticity_customer_complaints, condition_customer_complaints,
                                food_safety_issues, listing_policy_violations,
                                restricted_product_policy_violations, customer_review_policy_violations,
                                other_policy_violations, regulatory_compliance_issues,
                                order_defect_rate, negative_feedback_rate, a_to_z_rate, chargeback_rate,
                                late_shipment_rate, pre_fulfillment_cancel_rate, valid_tracking_rate, on_time_delivery_rate,
                                record_datetime, remark
                            ) VALUES (
                                %s, %s,
                                %s, %s,
                                %s, %s,
                                %s, %s,
                                %s, %s,
                                %s, %s,
                                %s, %s, %s, %s,
                                %s, %s, %s, %s,
                                %s, %s
                            )
                            """,
                            (
                                shop_id, values['account_health_rating'],
                                values['suspected_ip_infringement'], values['intellectual_property_complaints'],
                                values['authenticity_customer_complaints'], values['condition_customer_complaints'],
                                values['food_safety_issues'], values['listing_policy_violations'],
                                values['restricted_product_policy_violations'], values['customer_review_policy_violations'],
                                values['other_policy_violations'], values['regulatory_compliance_issues'],
                                values['order_defect_rate'], values['negative_feedback_rate'], values['a_to_z_rate'], values['chargeback_rate'],
                                values['late_shipment_rate'], values['pre_fulfillment_cancel_rate'], values['valid_tracking_rate'], values['on_time_delivery_rate'],
                                record_datetime, remark
                            )
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                shop_id = self._parse_int(data.get('shop_id'))
                if not item_id or not shop_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id or shop_id'}, start_response)

                values = {}
                for key in int_fields:
                    parsed = self._parse_int(data.get(key))
                    if parsed is None:
                        return self.send_json({'status': 'error', 'message': f'Missing or invalid {key}'}, start_response)
                    values[key] = parsed
                for key in percent_fields:
                    parsed = self._parse_float(data.get(key))
                    if parsed is None:
                        return self.send_json({'status': 'error', 'message': f'Missing or invalid {key}'}, start_response)
                    values[key] = parsed

                record_datetime = self._normalize_datetime_text(data.get('record_datetime')) or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                remark = (data.get('remark') or '').strip()[:500]

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT s.id
                            FROM shops s
                            JOIN platform_types pt ON pt.id = s.platform_type_id
                            WHERE s.id=%s AND LOWER(TRIM(pt.name))='amazon'
                            """,
                            (shop_id,)
                        )
                        allowed_shop = cur.fetchone()
                        if not allowed_shop:
                            return self.send_json({'status': 'error', 'message': 'Only Amazon platform shop is allowed'}, start_response)
                        cur.execute("SELECT id FROM amazon_account_health WHERE id=%s", (item_id,))
                        exists = cur.fetchone()
                        if not exists:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute(
                            """
                            UPDATE amazon_account_health
                            SET shop_id=%s,
                                account_health_rating=%s,
                                suspected_ip_infringement=%s,
                                intellectual_property_complaints=%s,
                                authenticity_customer_complaints=%s,
                                condition_customer_complaints=%s,
                                food_safety_issues=%s,
                                listing_policy_violations=%s,
                                restricted_product_policy_violations=%s,
                                customer_review_policy_violations=%s,
                                other_policy_violations=%s,
                                regulatory_compliance_issues=%s,
                                order_defect_rate=%s,
                                negative_feedback_rate=%s,
                                a_to_z_rate=%s,
                                chargeback_rate=%s,
                                late_shipment_rate=%s,
                                pre_fulfillment_cancel_rate=%s,
                                valid_tracking_rate=%s,
                                on_time_delivery_rate=%s,
                                record_datetime=%s,
                                remark=%s
                            WHERE id=%s
                            """,
                            (
                                shop_id,
                                values['account_health_rating'],
                                values['suspected_ip_infringement'],
                                values['intellectual_property_complaints'],
                                values['authenticity_customer_complaints'],
                                values['condition_customer_complaints'],
                                values['food_safety_issues'],
                                values['listing_policy_violations'],
                                values['restricted_product_policy_violations'],
                                values['customer_review_policy_violations'],
                                values['other_policy_violations'],
                                values['regulatory_compliance_issues'],
                                values['order_defect_rate'],
                                values['negative_feedback_rate'],
                                values['a_to_z_rate'],
                                values['chargeback_rate'],
                                values['late_shipment_rate'],
                                values['pre_fulfillment_cancel_rate'],
                                values['valid_tracking_rate'],
                                values['on_time_delivery_rate'],
                                record_datetime,
                                remark,
                                item_id
                            )
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_account_health WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            print("AmazonAccountHealth API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_account_health_template_api(self, environ, method, start_response):
        """Amazon 账户健康模板下载"""
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            self._ensure_amazon_account_health_table()
            shop_names = []
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT s.shop_name
                        FROM shops s
                        JOIN platform_types pt ON pt.id = s.platform_type_id
                        WHERE LOWER(TRIM(pt.name))='amazon'
                        ORDER BY s.shop_name
                        """
                    )
                    shop_names = [str(row.get('shop_name') or '').strip() for row in (cur.fetchall() or []) if str(row.get('shop_name') or '').strip()]

            wb = Workbook()
            ws = wb.active
            ws.title = 'amazon_account_health'

            headers = [
                '店铺*', '记录日期时间*', '账户状况评级*',
                '涉嫌侵犯知识产权*', '知识产权投诉*', '商品真实性买家投诉*', '商品状况买家投诉*',
                '食品和商品安全问题*', '上架政策违规*', '违反受限商品政策*', '违反买家商品评论政策*', '其他违反政策*', '监管合规性*',
                '订单缺陷率(%)*', '负面反馈(%)*', 'A-to-z(%)*', '信用卡拒付(%)*',
                '迟发率(%)*', '配送前取消率(%)*', '有效追踪率(%)*', '准时交货率(%)*',
                '备注'
            ]
            ws.append(headers)

            sample_shop = shop_names[0] if shop_names else ''
            ws.append([
                sample_shop, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 260,
                0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
                0.35, 0.00, 0.00, 0.00,
                1.20, 0.80, 97.50, 95.20,
                '示例行（请勿修改，此行不会导入）'
            ])

            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            for cell in ws[2]:
                cell.fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
                cell.font = Font(italic=True, color='888888')

            widths = [20, 20, 14, 16, 14, 18, 18, 18, 14, 18, 20, 14, 14, 14, 12, 12, 12, 12, 14, 14, 14, 28]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width

            options_ws = wb.create_sheet('options')
            options_ws.sheet_state = 'hidden'
            options_ws.cell(row=1, column=1, value='amazon_shop_name')
            for idx, name in enumerate(shop_names, start=2):
                options_ws.cell(row=idx, column=1, value=name)

            if shop_names:
                shop_validation = DataValidation(type='list', formula1=f'=options!$A$2:$A${len(shop_names) + 1}', allow_blank=False)
                ws.add_data_validation(shop_validation)
                for row_idx in range(3, 500):
                    shop_validation.add(f'A{row_idx}')

            ws.freeze_panes = 'A3'
            return self._send_excel_workbook(wb, 'amazon_account_health_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_account_health_import_api(self, environ, method, start_response):
        """Amazon 账户健康批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active
            headers = [str(cell.value or '').strip() for cell in ws[1]]
            header_map = {name: idx for idx, name in enumerate(headers)}

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx].value

            required_headers = [
                '店铺*', '记录日期时间*', '账户状况评级*',
                '涉嫌侵犯知识产权*', '知识产权投诉*', '商品真实性买家投诉*', '商品状况买家投诉*',
                '食品和商品安全问题*', '上架政策违规*', '违反受限商品政策*', '违反买家商品评论政策*', '其他违反政策*', '监管合规性*',
                '订单缺陷率(%)*', '负面反馈(%)*', 'A-to-z(%)*', '信用卡拒付(%)*',
                '迟发率(%)*', '配送前取消率(%)*', '有效追踪率(%)*', '准时交货率(%)*'
            ]
            for col_name in required_headers:
                if col_name not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {col_name}'}, start_response)

            self._ensure_amazon_account_health_table()
            created = 0
            updated = 0
            unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT s.id, s.shop_name
                        FROM shops s
                        JOIN platform_types pt ON pt.id = s.platform_type_id
                        WHERE LOWER(TRIM(pt.name))='amazon'
                        """
                    )
                    shop_rows = cur.fetchall() or []
                    shop_map = {str(row.get('shop_name') or '').strip(): int(row.get('id')) for row in shop_rows if row.get('id')}

                for row_idx in range(2, ws.max_row + 1):
                    if row_idx == 2:
                        continue
                    row = ws[row_idx]
                    if not any(cell.value is not None and str(cell.value).strip() for cell in row):
                        continue
                    try:
                        shop_name = str(get_cell(row, '店铺*') or '').strip()
                        shop_id = shop_map.get(shop_name)
                        if not shop_id:
                            raise ValueError(f'店铺不存在或非Amazon平台: {shop_name}')

                        record_datetime = self._normalize_datetime_text(get_cell(row, '记录日期时间*'))
                        if not record_datetime:
                            raise ValueError('记录日期时间格式错误，请使用 YYYY-MM-DD HH:MM:SS 或 YYYY-MM-DDTHH:MM')

                        parsed = {
                            'account_health_rating': self._parse_int(get_cell(row, '账户状况评级*')),
                            'suspected_ip_infringement': self._parse_int(get_cell(row, '涉嫌侵犯知识产权*')),
                            'intellectual_property_complaints': self._parse_int(get_cell(row, '知识产权投诉*')),
                            'authenticity_customer_complaints': self._parse_int(get_cell(row, '商品真实性买家投诉*')),
                            'condition_customer_complaints': self._parse_int(get_cell(row, '商品状况买家投诉*')),
                            'food_safety_issues': self._parse_int(get_cell(row, '食品和商品安全问题*')),
                            'listing_policy_violations': self._parse_int(get_cell(row, '上架政策违规*')),
                            'restricted_product_policy_violations': self._parse_int(get_cell(row, '违反受限商品政策*')),
                            'customer_review_policy_violations': self._parse_int(get_cell(row, '违反买家商品评论政策*')),
                            'other_policy_violations': self._parse_int(get_cell(row, '其他违反政策*')),
                            'regulatory_compliance_issues': self._parse_int(get_cell(row, '监管合规性*')),
                            'order_defect_rate': self._parse_float(get_cell(row, '订单缺陷率(%)*')),
                            'negative_feedback_rate': self._parse_float(get_cell(row, '负面反馈(%)*')),
                            'a_to_z_rate': self._parse_float(get_cell(row, 'A-to-z(%)*')),
                            'chargeback_rate': self._parse_float(get_cell(row, '信用卡拒付(%)*')),
                            'late_shipment_rate': self._parse_float(get_cell(row, '迟发率(%)*')),
                            'pre_fulfillment_cancel_rate': self._parse_float(get_cell(row, '配送前取消率(%)*')),
                            'valid_tracking_rate': self._parse_float(get_cell(row, '有效追踪率(%)*')),
                            'on_time_delivery_rate': self._parse_float(get_cell(row, '准时交货率(%)*')),
                            'remark': str(get_cell(row, '备注') or '').strip()[:500]
                        }

                        for key, value in parsed.items():
                            if key == 'remark':
                                continue
                            if value is None:
                                raise ValueError(f'{key} 为空或格式错误')

                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                SELECT * FROM amazon_account_health
                                WHERE shop_id=%s AND record_datetime=%s
                                ORDER BY id ASC
                                LIMIT 1
                                """,
                                (shop_id, record_datetime)
                            )
                            existing = cur.fetchone()

                            if existing:
                                cur.execute(
                                    """
                                    UPDATE amazon_account_health
                                    SET account_health_rating=%s,
                                        suspected_ip_infringement=%s,
                                        intellectual_property_complaints=%s,
                                        authenticity_customer_complaints=%s,
                                        condition_customer_complaints=%s,
                                        food_safety_issues=%s,
                                        listing_policy_violations=%s,
                                        restricted_product_policy_violations=%s,
                                        customer_review_policy_violations=%s,
                                        other_policy_violations=%s,
                                        regulatory_compliance_issues=%s,
                                        order_defect_rate=%s,
                                        negative_feedback_rate=%s,
                                        a_to_z_rate=%s,
                                        chargeback_rate=%s,
                                        late_shipment_rate=%s,
                                        pre_fulfillment_cancel_rate=%s,
                                        valid_tracking_rate=%s,
                                        on_time_delivery_rate=%s,
                                        remark=%s
                                    WHERE id=%s
                                    """,
                                    (
                                        parsed['account_health_rating'],
                                        parsed['suspected_ip_infringement'],
                                        parsed['intellectual_property_complaints'],
                                        parsed['authenticity_customer_complaints'],
                                        parsed['condition_customer_complaints'],
                                        parsed['food_safety_issues'],
                                        parsed['listing_policy_violations'],
                                        parsed['restricted_product_policy_violations'],
                                        parsed['customer_review_policy_violations'],
                                        parsed['other_policy_violations'],
                                        parsed['regulatory_compliance_issues'],
                                        parsed['order_defect_rate'],
                                        parsed['negative_feedback_rate'],
                                        parsed['a_to_z_rate'],
                                        parsed['chargeback_rate'],
                                        parsed['late_shipment_rate'],
                                        parsed['pre_fulfillment_cancel_rate'],
                                        parsed['valid_tracking_rate'],
                                        parsed['on_time_delivery_rate'],
                                        parsed['remark'],
                                        existing.get('id')
                                    )
                                )
                                if cur.rowcount:
                                    updated += 1
                                else:
                                    unchanged += 1
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO amazon_account_health (
                                        shop_id, account_health_rating,
                                        suspected_ip_infringement, intellectual_property_complaints,
                                        authenticity_customer_complaints, condition_customer_complaints,
                                        food_safety_issues, listing_policy_violations,
                                        restricted_product_policy_violations, customer_review_policy_violations,
                                        other_policy_violations, regulatory_compliance_issues,
                                        order_defect_rate, negative_feedback_rate, a_to_z_rate, chargeback_rate,
                                        late_shipment_rate, pre_fulfillment_cancel_rate, valid_tracking_rate, on_time_delivery_rate,
                                        record_datetime, remark
                                    ) VALUES (
                                        %s, %s,
                                        %s, %s,
                                        %s, %s,
                                        %s, %s,
                                        %s, %s,
                                        %s, %s,
                                        %s, %s, %s, %s,
                                        %s, %s, %s, %s,
                                        %s, %s
                                    )
                                    """,
                                    (
                                        shop_id, parsed['account_health_rating'],
                                        parsed['suspected_ip_infringement'], parsed['intellectual_property_complaints'],
                                        parsed['authenticity_customer_complaints'], parsed['condition_customer_complaints'],
                                        parsed['food_safety_issues'], parsed['listing_policy_violations'],
                                        parsed['restricted_product_policy_violations'], parsed['customer_review_policy_violations'],
                                        parsed['other_policy_violations'], parsed['regulatory_compliance_issues'],
                                        parsed['order_defect_rate'], parsed['negative_feedback_rate'], parsed['a_to_z_rate'], parsed['chargeback_rate'],
                                        parsed['late_shipment_rate'], parsed['pre_fulfillment_cancel_rate'], parsed['valid_tracking_rate'], parsed['on_time_delivery_rate'],
                                        record_datetime, parsed['remark']
                                    )
                                )
                                created += 1
                    except Exception as row_error:
                        errors.append({'row': row_idx, 'error': str(row_error)})

            return self.send_json({
                'status': 'success',
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'errors': errors
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


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

    def _get_logistics_link_root_bytes(self):
        return os.path.join(_RESOURCES_PARENT_BYTES, self._safe_fsencode('『物流仓储关联文件』'))

    def _ensure_logistics_bl_folder(self, bill_of_lading_no):
        name = (bill_of_lading_no or '').strip()
        if not name:
            return
        root = self._get_logistics_link_root_bytes()
        if not os.path.exists(root):
            os.makedirs(root, exist_ok=True)
        folder = os.path.join(root, self._safe_fsencode(name))
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        for sub in ('报关资料', '清关资料'):
            sub_folder = os.path.join(folder, self._safe_fsencode(sub))
            if not os.path.exists(sub_folder):
                os.makedirs(sub_folder, exist_ok=True)

    def _rename_logistics_bl_folder(self, old_no, new_no):
        old_name = (old_no or '').strip()
        new_name = (new_no or '').strip()
        if not old_name or not new_name or old_name == new_name:
            if new_name:
                self._ensure_logistics_bl_folder(new_name)
            return
        root = self._get_logistics_link_root_bytes()
        if not os.path.exists(root):
            os.makedirs(root, exist_ok=True)
        old_path = os.path.join(root, self._safe_fsencode(old_name))
        new_path = os.path.join(root, self._safe_fsencode(new_name))
        if os.path.exists(old_path):
            if os.path.exists(new_path):
                raise RuntimeError(f'目标提单目录已存在: {new_name}')
            os.rename(old_path, new_path)
        else:
            self._ensure_logistics_bl_folder(new_name)

    def _resolve_logistics_doc_folder(self, transit_id, doc_type):
        doc_kind = (doc_type or '').strip().lower()
        if doc_kind not in ('declaration', 'clearance'):
            raise RuntimeError('Invalid doc_type')
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT bill_of_lading_no FROM logistics_in_transit WHERE id=%s LIMIT 1", (transit_id,))
                row = cur.fetchone() or {}
        bill_no = (row.get('bill_of_lading_no') or '').strip()
        if not bill_no:
            raise RuntimeError('请先填写提单号后再操作资料文件')
        self._ensure_logistics_bl_folder(bill_no)
        sub_name = '报关资料' if doc_kind == 'declaration' else '清关资料'
        parent = os.path.join(self._get_logistics_link_root_bytes(), self._safe_fsencode(bill_no))
        folder = os.path.join(parent, self._safe_fsencode(sub_name))
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

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
























    def serve_file(self, filepath, content_type, start_response):
        """提供文件"""
        try:
            full_path = os.path.join(self.base_path, filepath)
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            content_bytes = content.encode('utf-8', errors='surrogatepass')
            start_response('200 OK', [
                ('Content-Type', content_type + '; charset=utf-8'),
                ('Content-Length', str(len(content_bytes)))
            ])
            return [content_bytes]
        except FileNotFoundError:
            return self.send_error(404, 'File Not Found', start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def serve_static(self, path, start_response):
        """提供静态文件"""
        try:
            filepath = os.path.join(self.base_path, path.lstrip('/'))

            with open(filepath, 'rb') as f:
                content = f.read()

            content_type, _ = mimetypes.guess_type(filepath)
            if content_type is None:
                content_type = 'application/octet-stream'

            start_response('200 OK', [
                ('Content-Type', content_type),
                ('Content-Length', str(len(content)))
            ])
            return [content]
        except FileNotFoundError:
            return self.send_error(404, 'File Not Found', start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def send_json(self, data, start_response):
        """发送 JSON 响应（确保完全ASCII编码）"""
        try:
            # Use UTF-8 with surrogatepass to safely encode any filesystem surrogate characters
            text = json.dumps(data, ensure_ascii=False, default=str)
            response = text.encode('utf-8', errors='surrogatepass')
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(response)))
            ])
            return [response]
        except Exception as e:
            print("JSON encoding error: " + str(e))
            try:
                fallback_text = json.dumps({'status': 'error', 'message': 'encoding error'}, ensure_ascii=False)
                fallback = fallback_text.encode('utf-8', errors='surrogatepass')
            except Exception:
                fallback = b'{"status":"error","message":"encoding error"}'
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(fallback)))
            ])
            return [fallback]
    
    def send_error(self, status_code, message, start_response):
        """发送错误响应"""
        status_text = {
            400: 'Bad Request',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            409: 'Conflict',
            500: 'Internal Server Error'
        }.get(status_code, 'Error')
        
        status = f'{status_code} {status_text}'
        
        error_html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>错误 {status_code}</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>{status}</h1>
            <p>{message}</p>
        </body>
        </html>
        '''.encode('utf-8', errors='surrogatepass')
        
        start_response(status, [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(error_html)))
        ])
        return [error_html]

# 运行时强制使用 mixin 版本的方法（过渡期）：
# 先确保拆分代码真正生效，再逐步删除 app.py 里的历史同名实现。
WSGIApp.handle_auth_api = AuthEmployeeMixin.handle_auth_api
WSGIApp.handle_employee_api = AuthEmployeeMixin.handle_employee_api

WSGIApp._dispatch_api_request = RequestRoutingMixin._dispatch_api_request
WSGIApp._validate_api_permission = RequestRoutingMixin._validate_api_permission
WSGIApp._dispatch_page_request = RequestRoutingMixin._dispatch_page_request

WSGIApp.handle_logistics_warehouse_api = LogisticsWarehouseMixin.handle_logistics_warehouse_api
WSGIApp.handle_logistics_warehouse_template_api = LogisticsWarehouseMixin.handle_logistics_warehouse_template_api
WSGIApp.handle_logistics_warehouse_import_api = LogisticsWarehouseMixin.handle_logistics_warehouse_import_api
WSGIApp.handle_logistics_warehouse_inventory_api = LogisticsWarehouseMixin.handle_logistics_warehouse_inventory_api
WSGIApp.handle_logistics_warehouse_inventory_template_api = LogisticsWarehouseMixin.handle_logistics_warehouse_inventory_template_api
WSGIApp.handle_logistics_warehouse_inventory_import_api = LogisticsWarehouseMixin.handle_logistics_warehouse_inventory_import_api
WSGIApp.handle_logistics_warehouse_dashboard_api = LogisticsWarehouseMixin.handle_logistics_warehouse_dashboard_api

WSGIApp.handle_logistics_in_transit_api = LogisticsInTransitMixin.handle_logistics_in_transit_api
WSGIApp.handle_logistics_in_transit_template_api = LogisticsInTransitMixin.handle_logistics_in_transit_template_api
WSGIApp.handle_logistics_in_transit_import_api = LogisticsInTransitMixin.handle_logistics_in_transit_import_api
WSGIApp.handle_logistics_in_transit_doc_upload_api = LogisticsInTransitMixin.handle_logistics_in_transit_doc_upload_api
WSGIApp.handle_logistics_in_transit_doc_files_api = LogisticsInTransitMixin.handle_logistics_in_transit_doc_files_api

WSGIApp.handle_parent_api = SalesProductMixin.handle_parent_api
WSGIApp.handle_sales_product_api = SalesProductMixin.handle_sales_product_api
WSGIApp.handle_sales_product_template_api = SalesProductMixin.handle_sales_product_template_api
WSGIApp.handle_sales_product_import_api = SalesProductMixin.handle_sales_product_import_api

WSGIApp.handle_sales_order_registration_api = SalesManagementMixin.handle_sales_order_registration_api
WSGIApp.handle_sales_order_registration_template_api = SalesManagementMixin.handle_sales_order_registration_template_api
WSGIApp.handle_sales_order_registration_import_api = SalesManagementMixin.handle_sales_order_registration_import_api

WSGIApp._ensure_logistics_tables = LogisticsSchemaMixin._ensure_logistics_tables
WSGIApp._ensure_factory_inventory_tables = LogisticsSchemaMixin._ensure_factory_inventory_tables
WSGIApp._ensure_sales_parent_tables = SalesSchemaMixin._ensure_sales_parent_tables
WSGIApp._ensure_sales_product_tables = SalesSchemaMixin._ensure_sales_product_tables
WSGIApp._ensure_sales_order_registration_tables = SalesSchemaMixin._ensure_sales_order_registration_tables

# WSGI 应用实例 - Web Station 会调用这个
application = WSGIApp()

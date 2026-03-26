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
    from amazon_account_health_mixin import AmazonAccountHealthMixin
    from support_domain_mixin import SupportDomainMixin
    from encoding_utils_mixin import EncodingUtilsMixin
    from image_processing_mixin import ImageProcessingMixin
    from file_utils_mixin import FileUtilsMixin
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
    class AmazonAccountHealthMixin: pass
    class SupportDomainMixin: pass
    class EncodingUtilsMixin: pass
    class ImageProcessingMixin: pass
    class FileUtilsMixin: pass

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

class WSGIApp(AppEntryMixin, PagePermissionMixin, AuthEmployeeMixin, DbSchemaBasicsMixin, CoreAppMixin, ExcelToolsMixin, FileManagementMixin, RequestRoutingMixin, LogisticsWarehouseMixin, LogisticsInTransitMixin, SalesProductMixin, SalesManagementMixin, ProductManagementMixin, FabricManagementMixin, OrderManagementMixin, UtilityMixin, AmazonAdMixin, AmazonAccountHealthMixin, SupportDomainMixin, EncodingUtilsMixin, ImageProcessingMixin, FileUtilsMixin):
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


    def _get_listing_folder_bytes(self):
        # RESOURCES_PATH_BYTES already points to the decoded child (上架资源),
        # so listing folder is the resources path itself.
        return RESOURCES_PATH_BYTES



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


    def _get_certification_folder_bytes(self):
        return self._join_resources('『认证』')


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







    def _get_logistics_link_root_bytes(self):
        return os.path.join(_RESOURCES_PARENT_BYTES, self._safe_fsencode('『物流仓储关联文件』'))


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

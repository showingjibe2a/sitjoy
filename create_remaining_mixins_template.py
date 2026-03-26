#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速批量提取脚本 - 从 app.py 提取多个 mixin 域
用法: python batch_extract_mixins.py
"""

import os
import re

def extract_method_block(content, method_name):
    """提取单个方法块"""
    pattern = rf'(\n    def {method_name}\(.*?\):)'
    match = re.search(pattern, content)
    if not match:
        return None
    
    start = match.start(1)
    rest = content[match.end():]
    next_method = re.search(r'\n    def ', rest)
    
    if next_method:
        end = match.end() + next_method.start()
    else:
        end = len(content)
    
    return content[start:end]

def create_fabric_mixin():
    """创建 fabric_mgmt_mixin.py"""
    with open('app.py', 'r', encoding='utf-8') as f:
        app_content = f.read()
    
    fabric_methods = [
        'handle_fabric_images_api',
        'handle_fabric_upload_api',
        'handle_fabric_image_delete_api',
        'handle_fabric_attach_api',
        'handle_fabric_api'
    ]
    
    # 收集方法
    methods_code = ""
    for method in fabric_methods:
        block = extract_method_block(app_content, method)
        if block:
            methods_code += block + "\n"
        else:
            print(f"  ⚠ 未找到 {method}")
    
    # 创建 mixin 文件
    mixin_content = '''# -*- coding: utf-8 -*-
import os
from urllib.parse import parse_qs

class FabricManagementMixin:
    """面料管理 Mixin：包含面料CRUD、图片上传、附件管理等"""
''' + methods_code

    with open('modules/fabric_mgmt_mixin.py', 'w', encoding='utf-8') as f:
        f.write(mixin_content)
    print("✓ 已创建 modules/fabric_mgmt_mixin.py")
    return True

def update_app_imports():
    """更新 app.py 导入和继承"""
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 添加导入
    if 'from fabric_mgmt_mixin import' not in content:
        content = content.replace(
            'from product_mgmt_mixin import ProductManagementMixin',
            'from product_mgmt_mixin import ProductManagementMixin\n    from fabric_mgmt_mixin import FabricManagementMixin'
        )
    
    # 添加继承
    if 'FabricManagementMixin' not in content:
        content = content.replace(
            'class WSGIApp(AppEntryMixin, PagePermissionMixin, AuthEmployeeMixin, DbSchemaBasicsMixin, CoreAppMixin, ExcelToolsMixin, FileManagementMixin, RequestRoutingMixin, LogisticsWarehouseMixin, LogisticsInTransitMixin, SalesProductMixin, SalesManagementMixin, ProductManagementMixin):',
            'class WSGIApp(AppEntryMixin, PagePermissionMixin, AuthEmployeeMixin, DbSchemaBasicsMixin, CoreAppMixin, ExcelToolsMixin, FileManagementMixin, RequestRoutingMixin, LogisticsWarehouseMixin, LogisticsInTransitMixin, SalesProductMixin, SalesManagementMixin, ProductManagementMixin, FabricManagementMixin):'
        )
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✓ 已更新 app.py 导入和继承")

if __name__ == '__main__':
    print("开始批量提取 Fabric Management Mixin...")
    try:
        create_fabric_mixin()
        update_app_imports()
        print("\n✓ Fabric Mixin 创建完成")
        print("  下一步: 运行 'python cleanup_app.py' 删除重复方法")
    except Exception as e:
        print(f"✗ 错误: {e}")

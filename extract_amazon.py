#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时脚本：从app.py提取Amazon Ad相关方法到amazon_ad_mixin.py"""

import re

# 要提取的方法列表
methods_to_extract = [
    'handle_amazon_ad_subtype_api',
    'handle_amazon_ad_operation_type_api',
    'handle_amazon_ad_api',
    'handle_amazon_ad_template_api',
    'handle_amazon_ad_import_api',
    'handle_amazon_ad_delivery_api',
    'handle_amazon_ad_product_api',
    'handle_amazon_ad_adjustment_api',
    'handle_amazon_ad_keyword_api',
    'handle_amazon_ad_keyword_template_api',
    'handle_amazon_ad_keyword_import_api',
]

# 读取app.py
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 提取方法
methods_code = []
for method_name in methods_to_extract:
    pattern = rf'(    def {method_name}\(.*?\n(?:.*?\n)*?    def |\Z)'
    match = re.search(pattern, content)
    if match:
        method_code = match.group(0)
        # 移除最后的"def"前缀（如果存在）
        if method_code.endswith('    def'):
            method_code = method_code[:-8]
        methods_code.append(method_code)
        print(f"✓ 找到 {method_name}")
    else:
        print(f"✗ 缺失 {method_name}")

# 生成amazon_ad_mixin.py
header = '''# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin"""

from urllib.parse import parse_qs
import pymysql.err

class AmazonAdMixin:
    """Amazon 广告管理 API 处理器"""

'''

# 写入文件
with open('modules/amazon_ad_mixin.py', 'w', encoding='utf-8') as f:
    f.write(header)
    for method_code in methods_code:
        f.write(method_code)
        f.write('\n')

print(f"\n✓ 已创建 amazon_ad_mixin.py，包含 {len(methods_code)} 个方法")

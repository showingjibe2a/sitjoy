#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时脚本：从app.py中删除已迁移到ProductManagementMixin的方法"""

import re

# 读取app.py
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 要删除的方法名称（按照字节顺序从后往前删除，避免行号变化问题）
methods_to_remove = [
    'handle_certification_api',          # 认证管理
    'handle_shop_api',                   # 店铺管理
    'handle_brand_api',                  # 品牌管理
    'handle_platform_type_api',          # 平台类型管理
]

def find_method_boundaries(content, method_name):
    """找到方法的开始和结束位置"""
    # 查找方法定义行
    pattern = rf'(\n    def {method_name}\(.*?\):)'
    match = re.search(pattern, content)
    if not match:
        return None, None
    
    start = match.start(1)  # 方法之前的换行符位置
    
    # 查找下一个同级别(4个缩进)的def
    rest = content[match.end():]
    next_method_match = re.search(r'\n    def ', rest)
    
    if next_method_match:
        end = match.end() + next_method_match.start()
    else:
        # 如果没有下一个方法，删除到文件末尾（或最后一个方法）
        end = len(content)
    
    return start, end

# 从后往前删除（避免前面的删除影响后面的位置）
for method_name in methods_to_remove:
    start, end = find_method_boundaries(content, method_name)
    if start is not None and end is not None:
        print(f"删除 {method_name}: {start}-{end}")
        # 删除方法，包括前面的换行符，但保留一个换行符
        content = content[:start] + '\n' + content[end:]
        print(f"  ✓ 已删除")
    else:
        print(f"⚠ 未找到 {method_name}")

# 也要删除 _replace_sku_family_fabric_ids（作为辅助方法）
supplementary_methods = [
    '_rename_listing_sku_folder',
    '_ensure_listing_sku_folder',
    '_replace_sku_family_fabric_ids',
]

# 但这些方法可能在其他地方使用，所以需要谨慎
# 暂时注释掉，只删除四个主要的API处理器

# 写回app.py
with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\n✓ 清理完成")

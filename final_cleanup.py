#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最终清理脚本：删除所有临时迁移文件、损坏的mixin、和配置文件"""

import os
import sys

# 要删除的临时文件列表
temp_files_to_delete = [
    'extract_amazon.py',           # 临时提取脚本（已用）
    'cleanup_app.py',              # 临时清理脚本（已用，可保留或删除）
    'modules/amazon_ad_mixin.py',  # 空的旧mixin文件
]

deleted_count = 0
error_count = 0

for filepath in temp_files_to_delete:
    abs_path = os.path.abspath(filepath)
    if os.path.exists(abs_path):
        try:
            os.remove(abs_path)
            print(f"✓ 已删除: {filepath}")
            deleted_count += 1
        except Exception as e:
            print(f"✗ 删除失败 {filepath}: {str(e)}")
            error_count += 1
    else:
        print(f"- 跳过 (不存在): {filepath}")

print(f"\n✓ 清理完成: 删除 {deleted_count} 个文件, {error_count} 个错误")

# 重命名amazon_ad_mixin_new.py为amazon_ad_mixin.py
old_name = 'modules/amazon_ad_mixin_new.py'
new_name = 'modules/amazon_ad_mixin.py'

if os.path.exists(old_name):
    try:
        # 先删除可能存在的旧文件
        if os.path.exists(new_name):
            os.remove(new_name)
        os.rename(old_name, new_name)
        print(f"✓ 已重命名: {old_name} -> {new_name}")
    except Exception as e:
        print(f"✗ 重命名失败: {str(e)}")
else:
    print(f"- {old_name} 不存在")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速提取脚本：从app.py提取方法到新mixin文件
使用方式：python extract_to_mixin.py <方法列表> <mixin名称>
"""

import re
import sys

def extract_methods_from_app(app_path, method_names):
    """从app.py中提取指定方法"""
    with open(app_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    content = ''.join(lines)
    extracted = {}
    
    for method_name in method_names:
        # 查找方法起始行
        pattern = rf'def {method_name}\(.*?\):'
        match = re.search(pattern, content)
        if not match:
            print(f"⚠ 未找到 {method_name}")
            continue
        
        # 找到该方法在lines中的起始位置
        method_start_pos = match.start()
        # 计算该位置在第几行
        start_line = content[:method_start_pos].count('\n')
        
        # 找到下一个同级别的def或类定义
        rest = content[match.end():]
        next_def_match = re.search(r'\n    def ', rest)
        
        if next_def_match:
            end_pos = match.end() + next_def_match.start()
            end_line = content[:end_pos].count('\n')
        else:
            end_line = len(lines)
        
        # 提取方法内容
        method_content = ''.join(lines[start_line:end_line]).rstrip()
        extracted[method_name] = (start_line, end_line, method_content)
        print(f"✓ 提取 {method_name}: 行 {start_line+1}-{end_line}")
    
    return extracted

if __name__ == '__main__':
    # 示例：提取fabric相关方法
    fabric_methods = [
        'handle_fabric_images_api',
        'handle_fabric_upload_api',
        'handle_fabric_image_delete_api', 
        'handle_fabric_attach_api',
        'handle_fabric_api'
    ]
    
    extracted = extract_methods_from_app('app.py', fabric_methods)
    
    if extracted:
        print(f"\n✓ 成功提取 {len(extracted)} 个方法")
        for method, (start, end, _) in extracted.items():
            print(f"  {method}: {start+1}-{end}")

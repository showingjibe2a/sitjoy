#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
恢复订单产品模板方法的脚本
"""
import os
import sys

def restore_methods():
    extracted_file = r'\\diskstation\web\sitjoy\temp_template_methods.py'
    mixin_file = r'\\diskstation\web\sitjoy\modules\order_mgmt_mixin.py'
    
    # Read extracted methods
    if not os.path.exists(extracted_file):
        print(f"ERROR: Extracted file not found: {extracted_file}")
        # Try from TEMP directory
        temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'template_methods_full.py')
        if os.path.exists(temp_path):
            extracted_file = temp_path
            print(f"Using temp file: {extracted_file}")
        else:
            print(f"ERROR: Neither file found")
            return False
    
    with open(extracted_file, 'r', encoding='utf-8') as f:
        extracted = f.read()
    
    # Find method positions
    method1_start = extracted.find('def handle_order_product_template_api')
    method2_start = extracted.find('def handle_order_product_import_api')
    method3_start = extracted.find('def _normalize_id_list', method2_start)
    
    print(f"Method 1 start: {method1_start}")
    print(f"Method 2 start: {method2_start}")
    print(f"Method 3 start: {method3_start}")
    
    if method1_start == -1 or method2_start == -1 or method3_start == -1:
        print("ERROR: Could not find all methods in extracted file")
        return False
    
    # Extract the two methods
    both_methods = extracted[method1_start:method3_start].rstrip()
    print(f"\nExtracted methods: {len(both_methods)} chars, {both_methods.count(chr(10))} lines")
    
    # Read current mixin file
    with open(mixin_file, 'r', encoding='utf-8') as f:
        mixin_content = f.read()
    
    # Find the methods in mixin file
    mixin_m1_start = mixin_content.find('def handle_order_product_template_api')
    mixin_m2_start = mixin_content.find('def handle_order_product_import_api')
    mixin_m3_start = mixin_content.find('def _normalize_id_list', mixin_m2_start)
    
    print(f"\nIn mixin file:")
    print(f"Method 1 at: {mixin_m1_start}")
    print(f"Method 2 at: {mixin_m2_start}")
    print(f"Method 3 at: {mixin_m3_start}")
    
    if mixin_m1_start == -1 or mixin_m2_start == -1 or mixin_m3_start == -1:
        print("ERROR: Could not find all methods in mixin file")
        return False
    
    # Replace the methods
    new_content = mixin_content[:mixin_m1_start] + both_methods + '\n\n' + mixin_content[mixin_m3_start:]
    
    # Write back
    with open(mixin_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"\nReplacement successful!")
    print(f"New mixin file size: {len(new_content)} chars")
    return True

if __name__ == '__main__':
    success = restore_methods()
    sys.exit(0 if success else 1)

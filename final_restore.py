#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Final template restoration script"""

import os
import sys

def main():
    extracted = r"C:\Users\W\AppData\Local\Temp\template_methods_full.py"
    mixin_file = r"\\diskstation\web\sitjoy\modules\order_mgmt_mixin.py"
    
    # Read files
    print("Reading files...")
    with open(extracted, 'r', encoding='utf-8') as f:
        new_methods = f.read()
    
    with open(mixin_file, 'r', encoding='utf-8') as f:
        mixin = f.read()
    
    print(f"New methods: {len(new_methods)} chars")
    print(f"Original mixin: {len(mixin)} chars")
    
    # Find where the methods should be replaced
    # Method 1: handle_order_product_template_api
    # Method 2: handle_order_product_import_api  
    # They span from method1 to just before _normalize_id_list
    
    m1_pos = mixin.find('    def handle_order_product_template_api')
    if m1_pos < 0:
        m1_pos = mixin.find('def handle_order_product_template_api')
    
    m3_pos = mixin.find('    def _normalize_id_list')
    
    if m1_pos < 0 or m3_pos < 0:
        print(f"ERROR: Could not find methods (m1={m1_pos}, m3={m3_pos})")
        return False
    
    print(f"Method 1 starts at char: {m1_pos}")
    print(f"Next method at char: {m3_pos}")
    
    # Construct new file
    new_mixin = mixin[:m1_pos] + new_methods + "\n\n" + mixin[m3_pos:]
    
    print(f"New mixin size: {len(new_mixin)} chars")
    
    # Write without BOM
    with open(mixin_file, 'w', encoding='utf-8-sig') as f:
        f.write(new_mixin)
    
    # Verify
    with open(mixin_file, 'r', encoding='utf-8') as f:
        verify = f.read()
    
    print(f"Verified written: {len(verify)} chars")
    
    # Check that methods are present
    if 'max_multi_columns' in verify and 'DataValidation' in verify and 'handle_order_product_import_api' in verify:
        print("✓ All key elements present!")
        return True
    else:
        print("✗ Some elements missing")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

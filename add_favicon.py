#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

templates_dir = 'templates'
favicon_link = '<link rel="icon" href="/static/favicon.ico" type="image/x-icon">'

count = 0
for filename in os.listdir(templates_dir):
    if not filename.endswith('.html'):
        continue
    
    filepath = os.path.join(templates_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否已经有favicon链接
    if 'favicon' in content or '/favicon' in content:
        print(f"⊘ {filename} (已有favicon)")
        continue
    
    # 找到</title>之后的位置
    if '</title>' in content:
        # 在</title>后插入favicon
        new_content = content.replace('</title>', '</title>\n    ' + favicon_link)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        count += 1
        print(f"✓ {filename}")

print(f"\n成功更新 {count} 个文件")

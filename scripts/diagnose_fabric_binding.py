#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
诊断面料图片绑定状态的脚本
用于排查为什么已绑定图片仍在未绑定列表中出现
"""

import os
import sys
import json
import base64
import unicodedata

# 添加父目录到路径以便导入 app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import WSGIApp
except ImportError as e:
    print(f"无法导入 app: {e}")
    print("请确保在项目根目录运行或设置 PYTHONPATH")
    sys.exit(1)

def utf8_to_b64(s):
    """将 utf-8 字符串编码为 base64"""
    return base64.b64encode(s.encode('utf-8')).decode('ascii')

def b64_to_utf8(b):
    """将 base64 解码为 utf-8 字符串"""
    try:
        return base64.b64decode(b).decode('utf-8')
    except Exception:
        return None

def main():
    print("=" * 80)
    print("面料图片绑定诊断工具")
    print("=" * 80)
    
    app = WSGIApp()
    
    # 1. 从数据库读取所有绑定记录
    print("\n[1] 从数据库读取已绑定图片...")
    try:
        with app._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, fabric_id, image_name, remark FROM fabric_images ORDER BY fabric_id, id")
                db_rows = cur.fetchall() or []
    except Exception as e:
        print(f"错误: 无法连接数据库 - {e}")
        return 1
    
    print(f"找到 {len(db_rows)} 条绑定记录")
    
    # 按 fabric_id 分组显示
    fabric_groups = {}
    for row in db_rows:
        fid = row.get('fabric_id')
        if fid not in fabric_groups:
            fabric_groups[fid] = []
        fabric_groups[fid].append(row)
    
    print(f"\n共 {len(fabric_groups)} 个面料有图片绑定:")
    for fid in sorted(fabric_groups.keys()):
        rows = fabric_groups[fid]
        print(f"  面料 ID {fid}: {len(rows)} 张图片")
        for r in rows[:3]:  # 只显示前3张
            print(f"    - {r.get('image_name')} ({r.get('remark')})")
        if len(rows) > 3:
            print(f"    ... 还有 {len(rows) - 3} 张")
    
    # 2. 扫描磁盘文件
    print("\n[2] 扫描磁盘面料文件...")
    folder = app._get_fabric_folder_bytes()
    if not os.path.exists(folder):
        print(f"错误: 面料文件夹不存在 - {folder}")
        return 1
    
    disk_files = []
    try:
        with os.scandir(folder) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False) and app._is_image_name(entry.name):
                    raw = entry.name
                    if isinstance(raw, str):
                        try:
                            raw_bytes = os.fsencode(raw)
                        except Exception:
                            raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                    else:
                        raw_bytes = raw
                    
                    try:
                        display = os.fsdecode(raw_bytes)
                    except Exception:
                        try:
                            display = raw_bytes.decode('utf-8')
                        except Exception:
                            display = raw_bytes.decode('latin-1', errors='replace')
                    
                    disk_files.append({
                        'raw_bytes': raw_bytes,
                        'display': display,
                        'b64': base64.b64encode(raw_bytes).decode('ascii')
                    })
    except Exception as e:
        print(f"错误: 无法扫描文件夹 - {e}")
        return 1
    
    print(f"找到 {len(disk_files)} 个图片文件")
    
    # 3. 构建变体映射（模拟后端逻辑）
    print("\n[3] 构建 Unicode 规范化变体映射...")
    bound_name_map = {}
    bound_b64_map = {}
    
    for row in db_rows:
        image_name = (row.get('image_name') or '').strip().replace('\\', '/')
        if not image_name:
            continue
        fid = row.get('fabric_id')
        
        # 提取文件名（去除可能的路径前缀）
        try:
            base = image_name.split('/')[-1].strip()
        except Exception:
            base = image_name
        
        if not base:
            continue
        
        # 规范化
        try:
            nfc = unicodedata.normalize('NFC', base)
        except Exception:
            nfc = base
        try:
            nfd = unicodedata.normalize('NFD', nfc)
        except Exception:
            nfd = nfc
        
        # 字符串变体
        for variant in (nfc, nfc.lower(), nfd, nfd.lower()):
            if not variant:
                continue
            if variant not in bound_name_map:
                bound_name_map[variant] = set()
            if fid is not None:
                bound_name_map[variant].add(int(fid))
        
        # base64 变体
        for variant in (nfc, nfd):
            try:
                b = os.fsencode(variant)
                b64 = base64.b64encode(b).decode('ascii')
                if b64 not in bound_b64_map:
                    bound_b64_map[b64] = set()
                if fid is not None:
                    bound_b64_map[b64].add(int(fid))
            except Exception:
                continue
    
    print(f"生成 {len(bound_name_map)} 个字符串变体, {len(bound_b64_map)} 个 base64 变体")
    
    # 4. 对每个磁盘文件进行匹配测试
    print("\n[4] 检查磁盘文件的绑定状态...")
    print("-" * 80)
    
    matched_count = 0
    unmatched_count = 0
    
    for file in disk_files:
        display = file['display']
        raw_bytes = file['raw_bytes']
        
        # 规范化显示名
        normalized_display = display.replace('\\', '/').split('/')[-1].strip()
        try:
            nd_nfc = unicodedata.normalize('NFC', normalized_display)
        except Exception:
            nd_nfc = normalized_display
        try:
            nd_nfd = unicodedata.normalize('NFD', nd_nfc)
        except Exception:
            nd_nfd = nd_nfc
        
        check_ids = set()
        
        # 字符串变体匹配
        for variant in (nd_nfc, nd_nfc.lower(), nd_nfd, nd_nfd.lower()):
            if variant:
                ids = bound_name_map.get(variant, set())
                if ids:
                    check_ids |= ids
        
        # base64 匹配（原始字节）
        try:
            b64_raw = base64.b64encode(raw_bytes).decode('ascii')
            ids = bound_b64_map.get(b64_raw, set())
            if ids:
                check_ids |= ids
        except Exception:
            pass
        
        # base64 匹配（规范化变体）
        for variant in (nd_nfc, nd_nfd):
            try:
                vb = os.fsencode(variant)
                b64_v = base64.b64encode(vb).decode('ascii')
                ids = bound_b64_map.get(b64_v, set())
                if ids:
                    check_ids |= ids
            except Exception:
                pass
        
        if check_ids:
            matched_count += 1
            print(f"✓ {normalized_display}")
            print(f"  -> 已绑定到面料: {sorted(check_ids)}")
        else:
            unmatched_count += 1
            print(f"✗ {normalized_display}")
            print(f"  -> 未绑定")
    
    print("-" * 80)
    print(f"\n总计: {len(disk_files)} 个文件, {matched_count} 个已绑定, {unmatched_count} 个未绑定")
    
    # 5. 检查是否有 DB 记录但磁盘文件不存在的情况
    print("\n[5] 检查孤立的数据库记录（文件不存在）...")
    disk_names = {f['display'] for f in disk_files}
    orphan_count = 0
    
    for fid, rows in fabric_groups.items():
        for row in rows:
            img_name = (row.get('image_name') or '').strip()
            # 提取文件名
            try:
                base_name = img_name.split('/')[-1].strip()
            except Exception:
                base_name = img_name
            
            if base_name and base_name not in disk_names:
                orphan_count += 1
                if orphan_count <= 10:  # 只显示前10个
                    print(f"  孤立记录 ID {row.get('id')}: {img_name} (面料 {fid})")
    
    if orphan_count > 10:
        print(f"  ... 还有 {orphan_count - 10} 条孤立记录")
    elif orphan_count == 0:
        print("  无孤立记录")
    
    print("\n" + "=" * 80)
    print("诊断完成!")
    print("=" * 80)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

# 最小的ICO文件（1x1像素BMP格式）
# 这是一个最小的有效的ICO文件
ico_data = bytes([
    # ICO文件头
    0x00, 0x00,           # 保留
    0x01, 0x00,           # 类型：1=ICO
    0x01, 0x00,           # 图像数量：1
    
    # 图像目录条目
    0x10, 0x10,           # 宽度：16
    0x10, 0x10,           # 高度：16
    0x00,                 # 颜色数：0（不使用）
    0x00,                 # 保留
    0x01, 0x00,           # 色平面
    0x20, 0x00,           # 比特数：32
    0x30, 0x00, 0x00, 0x00,  # 数据大小
    0x16, 0x00, 0x00, 0x00,  # 数据偏移
])

# BMP数据（16x16像素，32位RGBA）
# 简单的绿色方块
bmp_header = bytes([
    0x28, 0x00, 0x00, 0x00,  # DIB头大小
    0x10, 0x00, 0x00, 0x00,  # 宽度：16
    0x20, 0x00, 0x00, 0x00,  # 高度：32（包括透明度）
    0x01, 0x00,              # 色平面
    0x20, 0x00,              # 比特数：32
    0x00, 0x00, 0x00, 0x00,  # 压缩
    0x00, 0x00, 0x00, 0x00,  # 图像大小
    0x00, 0x00, 0x00, 0x00,  # 水平分辨率
    0x00, 0x00, 0x00, 0x00,  # 垂直分辨率
    0x00, 0x00, 0x00, 0x00,  # 颜色数
    0x00, 0x00, 0x00, 0x00,  # 重要颜色数
])

# 像素数据（绿色）
pixel_data = b'\x00\xa4\x4c\xff' * (16 * 16)  # RGB(76, 164, 0)，alpha=255

ico_file = ico_data + bmp_header + pixel_data

# 写入文件
output_path = os.path.join(os.path.dirname(__file__), 'static', 'favicon.ico')
os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'wb') as f:
    f.write(ico_file)
    
print(f"Favicon created at: {output_path}")

import re
import io
import cgi
import os
import json
import base64
import hashlib
from datetime import datetime
from urllib.parse import parse_qs

try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)

try:
    import pymysql
except Exception:
    pymysql = None


class SalesProductMixin:
    def handle_parent_api(self, environ, method, start_response):
        """父体管理 API（CRUD）"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            def limited_text(value, max_len):
                text = (value or '').strip()
                if not text:
                    return None
                if len(text) > max_len:
                    raise ValueError(f'文本长度超限（>{max_len}）')
                return text

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = """
                            SELECT sp.id, sp.parent_code, sp.is_enabled, sp.shop_id, sp.sku_marker,
                                   estimated_refund_rate, estimated_discount_rate,
                                   commission_rate, estimated_acoas,
                                   sp.created_at, sp.updated_at,
                                   s.shop_name, b.name AS brand_name, pt.name AS platform_type_name
                            FROM sales_parents sp
                            LEFT JOIN shops s ON s.id = sp.shop_id
                            LEFT JOIN brands b ON b.id = s.brand_id
                            LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                        """
                        params = []
                        filters = []
                        if item_id:
                            filters.append("sp.id = %s")
                            params.append(item_id)
                        if keyword:
                            like_kw = f"%{keyword}%"
                            filters.append("(sp.parent_code LIKE %s OR sp.sku_marker LIKE %s)")
                            params.extend([like_kw, like_kw])
                        if filters:
                            sql += " WHERE " + " AND ".join(filters)
                        sql += " ORDER BY sp.id DESC"
                        cur.execute(sql, params)
                        rows = cur.fetchall() or []
                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                parent_code = (data.get('parent_code') or '').strip()
                if not parent_code:
                    return self.send_json({'status': 'error', 'message': 'Missing parent_code'}, start_response)
                is_enabled_raw = data.get('is_enabled', 1)
                is_enabled = 1 if str(is_enabled_raw).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                shop_id = self._parse_int(data.get('shop_id'))
                try:
                    sku_marker = limited_text(data.get('sku_marker'), 128)
                except ValueError as ve:
                    return self.send_json({'status': 'error', 'message': str(ve)}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_parents
                            (parent_code, is_enabled, shop_id, sku_marker, estimated_refund_rate, estimated_discount_rate, commission_rate, estimated_acoas)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                parent_code,
                                is_enabled,
                                shop_id,
                                sku_marker,
                                self._parse_float(data.get('estimated_refund_rate')),
                                self._parse_float(data.get('estimated_discount_rate')),
                                self._parse_float(data.get('commission_rate')),
                                self._parse_float(data.get('estimated_acoas'))
                            )
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                is_enabled_raw = data.get('is_enabled', 1)
                is_enabled = 1 if str(is_enabled_raw).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                shop_id = self._parse_int(data.get('shop_id'))
                try:
                    sku_marker = limited_text(data.get('sku_marker'), 128)
                except ValueError as ve:
                    return self.send_json({'status': 'error', 'message': str(ve)}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE sales_parents
                            SET parent_code=%s,
                                is_enabled=%s,
                                shop_id=%s,
                                sku_marker=%s,
                                estimated_refund_rate=%s,
                                estimated_discount_rate=%s,
                                commission_rate=%s,
                                estimated_acoas=%s
                            WHERE id=%s
                            """,
                            (
                                (data.get('parent_code') or '').strip(),
                                is_enabled,
                                shop_id,
                                sku_marker,
                                self._parse_float(data.get('estimated_refund_rate')),
                                self._parse_float(data.get('estimated_discount_rate')),
                                self._parse_float(data.get('commission_rate')),
                                self._parse_float(data.get('estimated_acoas')),
                                item_id
                            )
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_parents WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_template_api(self, environ, method, start_response):
        """销售产品模板下载"""
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
            
            from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
            from openpyxl.worksheet.datavalidation import DataValidation

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            selected_ids = []
            for raw in query_params.get('ids', []):
                for token in re.split(r'[,，;；\s]+', str(raw or '').strip()):
                    if not token:
                        continue
                    item_id = self._parse_int(token)
                    if item_id and item_id not in selected_ids:
                        selected_ids.append(item_id)
            
            wb = Workbook()
            ws = wb.active
            ws.title = 'sales_products'

            # 获取可选项
            with self._get_db_connection() as conn:
                def _load_sales_template_options():
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, shop_name FROM shops ORDER BY shop_name")
                        shop_options_local = [row for row in (cur.fetchall() or []) if row.get('shop_name')]
                        cur.execute("SELECT parent_code FROM sales_parents ORDER BY parent_code")
                        parent_codes_local = [row['parent_code'] for row in cur.fetchall()]
                        cur.execute("SELECT sku_family FROM product_families ORDER BY sku_family")
                        sku_family_local = [str(row['sku_family']).strip() for row in (cur.fetchall() or []) if row.get('sku_family')]
                        cur.execute("SELECT fabric_name_en FROM fabric_materials ORDER BY fabric_name_en")
                        fabric_local = [str(row['fabric_name_en']).strip() for row in (cur.fetchall() or []) if row.get('fabric_name_en')]
                    return (shop_options_local, parent_codes_local, sku_family_local, fabric_local)

                shop_options, parent_codes, sku_family_options, fabric_options = self._get_cached_template_options(
                    'sales_product_template_options_v1',
                    _load_sales_template_options,
                    ttl_seconds=180
                )

                export_rows = []
                if selected_ids:
                    placeholders = ','.join(['%s'] * len(selected_ids))
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT sp.id, sp.product_status, sh.shop_name, pa.parent_code, pa.sku_marker,
                                sp.platform_sku, sp.child_code, sp.dachene_yuncang_no,
                                pf.sku_family, sp.spec_name, sp.fabric,
                                sp.sale_price_usd, sp.warehouse_cost_usd, sp.last_mile_cost_usd,
                                sp.net_weight_lbs, sp.package_length_in, sp.package_width_in, sp.package_height_in, sp.gross_weight_lbs
                            FROM sales_products sp
                            LEFT JOIN shops sh ON sh.id = sp.shop_id
                            LEFT JOIN sales_parents pa ON pa.id = sp.parent_id
                            LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                            WHERE sp.id IN ({placeholders})
                            ORDER BY sp.id DESC
                            """,
                            selected_ids
                        )
                        rows = cur.fetchall() or []
                        cur.execute(
                            f"""
                            SELECT l.sales_product_id, op.sku, l.quantity
                            FROM sales_product_order_links l
                            JOIN order_products op ON op.id = l.order_product_id
                            WHERE l.sales_product_id IN ({placeholders})
                            ORDER BY l.sales_product_id, op.sku
                            """,
                            selected_ids
                        )
                        link_rows = cur.fetchall() or []
                    link_map = {}
                    for link in link_rows:
                        sp_id = int(link.get('sales_product_id') or 0)
                        if not sp_id:
                            continue
                        sku = str(link.get('sku') or '').strip()
                        qty = int(link.get('quantity') or 1)
                        if not sku:
                            continue
                        link_map.setdefault(sp_id, []).append(f"{sku}*{qty}")
                    for row in rows:
                        export_rows.append([
                            {'enabled': '启用', 'retained': '留用', 'discarded': '弃用'}.get(str(row.get('product_status') or '').strip(), '启用'),
                            row.get('shop_name') or '',
                            row.get('parent_code') or '',
                            row.get('sku_marker') or '',
                            row.get('platform_sku') or '',
                            row.get('child_code') or '',
                            row.get('dachene_yuncang_no') or '',
                            row.get('sku_family') or '',
                            row.get('spec_name') or '',
                            row.get('fabric') or '',
                            '\n'.join(link_map.get(int(row.get('id') or 0), [])),
                            row.get('sale_price_usd') or '',
                            row.get('warehouse_cost_usd') or '',
                            row.get('last_mile_cost_usd') or '',
                            row.get('net_weight_lbs') or '',
                            row.get('package_length_in') or '',
                            row.get('package_width_in') or '',
                            row.get('package_height_in') or '',
                            row.get('gross_weight_lbs') or ''
                        ])
            
            # 第1行：模块标题（合并单元格）
            section_headers = [
                ('产品状态', 1, 1),
                ('父体关联', 2, 4),
                ('基础信息', 5, 10),
                ('销售信息', 11, 11),
                ('成本', 12, 14),
                ('包裹尺寸/重量', 15, 19)
            ]
            # 第2行：字段标题
            cn_headers = [
                '产品状态(启用/留用/弃用)',
                '店铺(必填)', '父体编号', '新父体SKU标识(父体不存在时选填)',
                '销售平台SKU', '子体编号', '大健云仓编号(选填，需先在下单产品管理页维护子Item Code)', '货号', '规格名称', '面料',
                '关联下单SKU及数量(必填，支持换行|;分隔，示例:MS01A-Brown*2)',
                '售价(USD)', '产品成本及发货至海外仓成本估算(USD，不含仓储费)(自动)', '尾程物流成本(自动)',
                '净重(lbs,自动)',
                '包裹长(in,自动)', '包裹宽(in,自动)', '包裹高(in,自动)', '毛重(lbs,自动)'
            ]

            ws.append([''] * len(cn_headers))
            ws.append(cn_headers)
            header_font = Font(bold=True, color='2A2420', size=11)
            header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            thin_border = Border(
                left=Side(style='thin', color='B7AEA4'),
                right=Side(style='thin', color='B7AEA4'),
                top=Side(style='thin', color='B7AEA4'),
                bottom=Side(style='thin', color='B7AEA4')
            )

            header_fill_by_col = ['D3D3D3'] * len(cn_headers)
            for col in range(1, len(cn_headers) + 1):
                cell = ws.cell(row=1, column=col)
                cell.font = header_font
                cell.alignment = header_alignment
                cell.border = thin_border

            for idx, (title, start_col, end_col) in enumerate(section_headers):
                if end_col > start_col:
                    ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=end_col)
                ws.cell(row=1, column=start_col).value = title
                if hasattr(self, '_get_morandi_section_color_pair'):
                    title_color, sub_header_color = self._get_morandi_section_color_pair(idx)
                else:
                    palette = [('A8B9A5', 'DDE7DB'), ('D7C894', 'ECE5CE')]
                    title_color, sub_header_color = palette[idx % len(palette)]
                fill = PatternFill(start_color=title_color, end_color=title_color, fill_type='solid')
                for col in range(start_col, end_col + 1):
                    header_fill_by_col[col - 1] = sub_header_color
                    ws.cell(row=1, column=col).fill = fill
                    ws.cell(row=1, column=col).border = thin_border

            for idx, cell in enumerate(ws[2], start=1):
                header_color = header_fill_by_col[idx - 1] if idx - 1 < len(header_fill_by_col) else 'D3D3D3'
                header_fill = PatternFill(start_color=header_color, end_color=header_color, fill_type='solid')
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = header_alignment
                cell.border = thin_border
            
            # 第3行：示例行（有勾选导出时改为导出数据）
            if export_rows:
                for row in export_rows:
                    ws.append(row)
            else:
                ws.append([
                    '启用',
                    '',
                    'PARENT-001',
                    'MS01-MARKER',
                    'MS01-Brown-1A',
                    'CHILD-001',
                    'DACHENE-001',
                    'MS01',
                    'A款',
                    '棕色/Brown',
                    'Recliner Sofa for Living Room',
                    'MS01A-Brown*2\nMS01B-Gray',
                    199.99,
                    '',
                    '',
                    '',
                    '', '', '', ''
                ])
                example_fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
                example_font = Font(italic=True, color='888888')
                for cell in ws[3]:
                    cell.fill = example_fill
                    cell.font = example_font
            
            # 添加数据验证
            status_validation = DataValidation(type='list', formula1='"启用,留用,弃用"', allow_blank=True)
            ws.add_data_validation(status_validation)
            max_validation_row = 400
            for row in range(4, max_validation_row + 1):
                status_validation.add(f'A{row}')

            if shop_options:
                shop_names = [str(row.get('shop_name')).strip() for row in shop_options if row.get('shop_name')]
                shop_names = [name for name in shop_names if name]
                if shop_names:
                    shop_validation = DataValidation(type='list', formula1=f'"{",".join(shop_names[:100])}"', allow_blank=False)
                    ws.add_data_validation(shop_validation)
                    for row in range(4, max_validation_row + 1):
                        shop_validation.add(f'B{row}')

            if sku_family_options:
                sku_validation = DataValidation(type='list', formula1=f'"{",".join(sku_family_options[:100])}"', allow_blank=True)
                ws.add_data_validation(sku_validation)
                for row in range(4, max_validation_row + 1):
                    sku_validation.add(f'H{row}')

            if fabric_options:
                fabric_validation = DataValidation(type='list', formula1=f'"{",".join(fabric_options[:100])}"', allow_blank=True)
                ws.add_data_validation(fabric_validation)
                for row in range(4, max_validation_row + 1):
                    fabric_validation.add(f'J{row}')

            if parent_codes:
                parent_validation = DataValidation(type='list', formula1=f'"{",".join(parent_codes[:100])}"', allow_blank=True)
                ws.add_data_validation(parent_validation)
                for row in range(4, max_validation_row + 1):
                    parent_validation.add(f'C{row}')
            
            
            # 设置列宽
            ws.column_dimensions['A'].width = 16
            ws.column_dimensions['B'].width = 12
            ws.column_dimensions['C'].width = 14
            ws.column_dimensions['D'].width = 22
            ws.column_dimensions['E'].width = 18
            ws.column_dimensions['F'].width = 12
            ws.column_dimensions['G'].width = 34
            ws.column_dimensions['H'].width = 14
            ws.column_dimensions['I'].width = 15
            ws.column_dimensions['J'].width = 24
            ws.column_dimensions['K'].width = 36
            ws.column_dimensions['L'].width = 24
            ws.column_dimensions['M'].width = 14
            ws.column_dimensions['N'].width = 16
            ws.column_dimensions['O'].width = 16
            ws.column_dimensions['P'].width = 14
            ws.column_dimensions['Q'].width = 14
            ws.column_dimensions['R'].width = 14
            ws.column_dimensions['S'].width = 14
            ws.column_dimensions['T'].width = 14
            
            ws.freeze_panes = 'A4'
            
            return self._send_excel_workbook(wb, 'sales_product_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_import_api(self, environ, method, start_response):
        """销售产品批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            preview_mode = str((query_params.get('preview', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            file_bytes = self._sanitize_xlsx_bool_cells(file_bytes)

            try:
                wb = load_workbook(io.BytesIO(file_bytes))
            except Exception as e:
                if 'Cannot be converted to bool' in str(e):
                    wb = self._rebuild_workbook_from_xlsx_xml(file_bytes)
                    if wb is None:
                        diag = self._scan_xlsx_invalid_bool_cells(file_bytes)
                        return self.send_json({
                            'status': 'error',
                            'message': (
                                '导入失败：文件中存在异常布尔字段且无法自动修复，'
                                '请另存为新的xlsx后重试'
                            ),
                            'debug': {
                                'cause': 'Cannot be converted to bool',
                                'invalid_bool_cells': diag.get('count', 0),
                                'samples': diag.get('samples', [])
                            }
                        }, start_response)
                else:
                    return self.send_json({'status': 'error', 'message': str(e)}, start_response)

            for sheet in wb.worksheets:
                for row in sheet.iter_rows():
                    for cell in row:
                        if cell.data_type == 'b' and not isinstance(cell.value, bool):
                            cell.data_type = 's'
                            cell.value = str(cell.value)

            ws = wb.active

            # 智能检测标题行：扫描前5行，找到包含关键字段的行作为标题行
            header_row_idx = 1
            key_indicators = ['店铺', '销售平台SKU', '父体编号', '关联下单SKU', 'shop', 'platform_sku', 'parent_code']
            for row_check in range(1, min(6, ws.max_row + 1)):
                row_cells = [str(cell.value or '').strip() for cell in ws[row_check]]
                row_text = '|'.join(row_cells).lower()
                # 检查是否包含关键指示字段
                if any(key.lower() in row_text for key in key_indicators):
                    header_row_idx = row_check
                    break
            
            headers = [cell.value for cell in ws[header_row_idx]]
            
            # 中文标签到字段代码的映射
            label_to_code = {
                '产品状态(启用/留用/弃用)': 'product_status',
                '店铺(必填)': 'shop_name',
                '店铺(可选)': 'shop_name',
                '店铺': 'shop_name',
                '平台SKU': 'platform_sku',
                '销售平台SKU': 'platform_sku',
                '父体编号': 'parent_code',
                '新父体SKU标识(父体不存在时选填)': 'parent_sku_marker',
                '子体编号': 'child_code',
                '大健云仓编号': 'dachene_yuncang_no',
                '大健云仓编号(选填，需先在下单产品管理页维护子Item Code)': 'dachene_yuncang_no',
                '货号': 'sku_family',
                '面料(选填)': 'fabric',
                '规格名(选填)': 'spec_name',
                '面料': 'fabric',
                '规格名称': 'spec_name',
                '关联下单SKU\n(支持换行|;分隔)': 'order_sku_links',
                '关联下单SKU及数量(必填，支持换行|;分隔，示例:MS01A-Brown*2)': 'order_sku_links',
                '售价(USD)': 'sale_price_usd',
                '产品成本及发货至海外仓成本估算(USD，不含仓储费)': 'warehouse_cost_usd',
                '产品成本及发货至海外仓成本估算(USD，不含仓储费)(自动)': 'warehouse_cost_usd',
                '海外仓成本(自动)': 'warehouse_cost_usd',
                '尾程物流成本(自动)': 'last_mile_cost_usd',
                '包裹长(in,自动)': 'package_length_in',
                '包裹宽(in,自动)': 'package_width_in',
                '包裹高(in,自动)': 'package_height_in',
                '净重(lbs,自动)': 'net_weight_lbs',
                '毛重(lbs,自动)': 'gross_weight_lbs',
                '组装后长(in)': 'finished_length_in',
                '组装后宽(in)': 'finished_width_in',
                '组装后高(in)': 'finished_height_in',
                # 兼容旧字段名
                'shop_name': 'shop_name',
                'brand_name': 'brand_name',
                'platform_type': 'platform_type',
                'product_status': 'product_status',
                'platform_sku': 'platform_sku',
                'parent_asin': 'parent_code',
                'child_asin': 'child_code',
                'dachene_yuncang_no': 'dachene_yuncang_no',
                'sku_family': 'sku_family',
                'fabric': 'fabric',
                'spec_name': 'spec_name',
                'sale_price_usd': 'sale_price_usd',
                'finished_length_in': 'finished_length_in',
                'finished_width_in': 'finished_width_in',
                'finished_height_in': 'finished_height_in',
                'assembled_length_in': 'finished_length_in',
                'assembled_width_in': 'finished_width_in',
                'assembled_height_in': 'finished_height_in',
                'order_sku_links': 'order_sku_links'
            }
            
            # 构建列映射，支持中文和旧格式
            header_map = {}
            for idx, h in enumerate(headers):
                if h is not None:
                    h_str = str(h).strip()
                    if h_str:  # 只处理非空的列标题
                        field_code = label_to_code.get(h_str, h_str)
                        if field_code not in header_map:  # 避免后面的重复列覆盖前面的
                            header_map[field_code] = idx
            
            # 诊断：保存所有读到的列（含None和空值）供调试
            detected_headers = [str(h).strip() if h else '[空]' for h in headers]
            detected_headers_non_empty = [h for h in detected_headers if h != '[空]']
            has_shop_name_column = 'shop_name' in header_map

            # 如果预检发现没有shop_name列，立即返回诊断信息
            if not has_shop_name_column:
                return self.send_json({
                    'status': 'error',
                    'message': (
                        f'导入失败：找不到店铺列。系统在第 {header_row_idx} 行检测到了以下列标题：\n'
                        f'{", ".join(detected_headers_non_empty) if detected_headers_non_empty else "[无有效列标题]"}\n\n'
                        f'请确保Excel中包含"店铺(必填)"或"店铺"列。'
                        f'如果列标题位置与预期不符，请重新下载模板并按照模板格式整理数据。'
                    ),
                    'detected_headers': detected_headers,
                    'detected_header_row': header_row_idx,
                    'detected_headers_count': len(detected_headers_non_empty),
                    'expected_shop_column_names': ['店铺(必填)', '店铺(可选)', '店铺', 'shop_name']
                }, start_response)

            def get_cell(row, key):
                idx = header_map.get(key)
                if idx is None:
                    return None
                return row[idx].value

            def parse_links(raw):
                """解析 order_sku_links：支持换行/分号/竖线/逗号分隔，重复SKU自动汇总数量"""
                if raw is None:
                    return []
                text = str(raw).strip()
                if not text:
                    return []
                
                # 支持换行符、分号、竖线、逗号分隔
                parts = [t.strip() for t in re.split(r'[\n\r;；|,，]+', text) if t.strip()]
                sku_qty_map = {}
                
                for part in parts:
                    if '*' in part:
                        sku, qty = part.split('*', 1)
                    else:
                        sku, qty = part, None
                    
                    sku = sku.strip()
                    if not sku:
                        continue
                    
                    if qty is None:
                        qty_val = 1
                    else:
                        qty = qty.strip()
                        try:
                            qty_val = int(qty) if qty else 1
                        except Exception:
                            qty_val = 1

                    sku_qty_map[sku] = sku_qty_map.get(sku, 0) + max(1, qty_val)

                return [(sku, qty) for sku, qty in sku_qty_map.items() if qty > 0]

            def link_signature(entries):
                if not entries:
                    return tuple()
                return tuple(sorted((int(e.get('order_product_id')), int(e.get('quantity') or 1)) for e in entries if e.get('order_product_id')))

            def aggregate_order_links(links):
                if not links:
                    return {
                        'auto_fabric': '',
                        'auto_spec_name': '',
                        'first_fabric_code': '',
                        'sku_family_id': None,
                        'warehouse_cost_usd': 0.0,
                        'last_mile_cost_usd': 0.0,
                        'package_length_in': 0.0,
                        'package_width_in': 0.0,
                        'package_height_in': 0.0,
                        'net_weight_lbs': 0.0,
                        'gross_weight_lbs': 0.0
                    }

                fabrics = []
                spec_parts = []
                sku_family_id = None
                warehouse_cost_usd = 0.0
                last_mile_cost_usd = 0.0
                package_length_in = 0.0
                package_width_in = 0.0
                package_height_in = 0.0
                net_weight_lbs = 0.0
                gross_weight_lbs = 0.0

                for entry in links:
                    row = order_detail_by_id.get(entry['order_product_id'])
                    if not row:
                        continue
                    qty = max(1, int(entry.get('quantity') or 1))
                    if sku_family_id is None:
                        sku_family_id = row.get('sku_family_id')

                    fabric_code = self._code_before_dash(row.get('fabric_code'))
                    if not fabric_code:
                        fabric_code = self._code_before_dash(row.get('fabric_name_en'))
                    if fabric_code and fabric_code not in fabrics:
                        fabrics.append(fabric_code)

                    spec_short = (row.get('spec_qty_short') or '').strip()
                    if spec_short:
                        spec_parts.append(f"{qty}{spec_short}")

                    warehouse_cost_usd += float(row.get('cost_usd') or 0) * qty
                    last_mile_cost_usd += float(row.get('last_mile_avg_freight_usd') or 0) * qty
                    package_length_in = max(package_length_in, float(row.get('package_length_in') or 0))
                    package_width_in = max(package_width_in, float(row.get('package_width_in') or 0))
                    package_height_in = max(package_height_in, float(row.get('package_height_in') or 0))
                    net_weight_lbs += float(row.get('net_weight_lbs') or 0) * qty
                    gross_weight_lbs += float(row.get('gross_weight_lbs') or 0) * qty

                return {
                    'auto_fabric': ' / '.join(fabrics),
                    'auto_spec_name': ''.join(spec_parts),
                    'first_fabric_code': fabrics[0] if fabrics else '',
                    'sku_family_id': sku_family_id,
                    'warehouse_cost_usd': round(warehouse_cost_usd, 2),
                    'last_mile_cost_usd': round(last_mile_cost_usd, 2),
                    'package_length_in': round(package_length_in, 2),
                    'package_width_in': round(package_width_in, 2),
                    'package_height_in': round(package_height_in, 2),
                    'net_weight_lbs': round(net_weight_lbs, 2),
                    'gross_weight_lbs': round(gross_weight_lbs, 2)
                }

            with self._get_db_connection() as conn:
                tx_enabled = False
                if not preview_mode:
                    try:
                        conn.autocommit(False)
                        tx_enabled = True
                    except Exception:
                        tx_enabled = False

                with conn.cursor() as cur:
                    cur.execute("SELECT id, parent_code, shop_id FROM sales_parents")
                    parent_map = {row['parent_code']: row for row in (cur.fetchall() or [])}

                    cur.execute("SELECT id, shop_name FROM shops")
                    shop_map = {str(row['shop_name']).strip(): row['id'] for row in (cur.fetchall() or []) if row.get('shop_name')}

                    cur.execute(
                        """
                        SELECT op.id, op.sku, op.sku_family_id, op.spec_qty_short,
                               op.cost_usd, op.last_mile_avg_freight_usd,
                               op.finished_length_in, op.finished_width_in, op.finished_height_in,
                               op.package_length_in, op.package_width_in, op.package_height_in,
                               op.net_weight_lbs, op.gross_weight_lbs,
                               fm.fabric_code, fm.fabric_name_en
                        FROM order_products op
                        LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                        """
                    )
                    order_rows = cur.fetchall() or []
                    order_map = {row['sku']: row['id'] for row in order_rows if row.get('sku')}
                    order_detail_by_id = {row['id']: row for row in order_rows if row.get('id')}

                    cur.execute("SELECT id, sku_family FROM product_families")
                    sku_family_rows = cur.fetchall() or []
                    sku_family_map = {str(row['sku_family']).strip(): row['id'] for row in sku_family_rows if row.get('sku_family')}
                    sku_family_code_map = {row['id']: (row.get('sku_family') or '').strip() for row in sku_family_rows if row.get('id')}

                    cur.execute("SELECT id, platform_sku FROM sales_products")
                    sales_map = {row['platform_sku']: row['id'] for row in cur.fetchall()}

                    cur.execute(
                        """
                        SELECT sp.platform_sku, spol.order_product_id, spol.quantity
                        FROM sales_products sp
                        LEFT JOIN sales_product_order_links spol ON spol.sales_product_id = sp.id
                        """
                    )
                    existing_link_map = {}
                    for row in (cur.fetchall() or []):
                        sku = row.get('platform_sku')
                        if not sku:
                            continue
                        existing_link_map.setdefault(sku, [])
                        if row.get('order_product_id'):
                            existing_link_map[sku].append((int(row['order_product_id']), int(row.get('quantity') or 1)))
                    for sku in list(existing_link_map.keys()):
                        existing_link_map[sku] = tuple(sorted(existing_link_map[sku]))

                created = 0
                updated = 0
                unchanged = 0
                relation_created = 0
                relation_deleted = 0
                total_rows = 0
                errors = []
                data_start_row = header_row_idx + 2
                
                # 批处理缓冲区
                batch_updates = []  # [(payload_with_id), ...]
                batch_inserts = []  # [(payload), ...]
                batch_insert_skus = []  # 临时缓冲，flush 时清空
                all_new_insert_skus = []  # 全局累积，记录循环中所有新插入的 SKU
                batch_links = []    # [(platform_sku, target_id, new_link_sig, old_link_sig, link_entries), ...]
                batch_flush_size = 200
                
                def flush_batch_writes(cur):
                    """批量提交到数据库"""
                    nonlocal batch_updates, batch_inserts, batch_insert_skus, all_new_insert_skus
                    if batch_updates:
                        # 用逐行 execute 执行所有 UPDATE（保持单个游标活跃）
                        try:
                            for payload in batch_updates:
                                cur.execute(
                                    """
                                    UPDATE sales_products
                                    SET shop_id=%s, platform_sku=%s, product_status=%s, sku_family_id=%s,
                                        parent_id=%s, child_code=%s, dachene_yuncang_no=%s, fabric=%s, spec_name=%s,
                                        sale_price_usd=%s, warehouse_cost_usd=%s, last_mile_cost_usd=%s,
                                        package_length_in=%s, package_width_in=%s, package_height_in=%s,
                                        net_weight_lbs=%s, gross_weight_lbs=%s
                                    WHERE id=%s
                                    """,
                                    payload
                                )
                        except Exception as e:
                            errors.append({'error': f'批量更新失败: {str(e)}'})
                        batch_updates = []
                    
                    if batch_inserts:
                        # 用多行 INSERT VALUES 一次性批量插入（pymysql 支持）
                        insert_ok = False
                        try:
                            if batch_inserts:
                                # 构建多行 VALUES 语句
                                placeholders = ','.join(['(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'] * len(batch_inserts))
                                insert_values = []
                                for payload in batch_inserts:
                                    insert_values.extend(payload)
                                
                                cur.execute(
                                    f"""
                                    INSERT INTO sales_products
                                        (shop_id, platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no, fabric, spec_name,
                                     sale_price_usd, warehouse_cost_usd, last_mile_cost_usd,
                                     package_length_in, package_width_in, package_height_in,
                                     net_weight_lbs, gross_weight_lbs)
                                    VALUES {placeholders}
                                    """,
                                    insert_values
                                )
                                insert_ok = True
                        except Exception as e:
                            errors.append({'error': f'批量插入失败: {str(e)}'})
                        
                        # 仅在插入成功后，记录本次新插入 SKU
                        if insert_ok:
                            all_new_insert_skus.extend(batch_insert_skus)
                        batch_inserts = []
                        batch_insert_skus = []
                
                with conn.cursor() as row_cur:
                    for row_idx in range(data_start_row, ws.max_row + 1):
                        row = ws[row_idx]
                        row_values = [cell.value for cell in row]
                        if not any(v is not None and str(v).strip() for v in row_values):
                            continue
                        total_rows += 1

                        # 支持两种格式：新的合并列 vs 旧的分开列
                        platform_sku = (get_cell(row, 'platform_sku') or '').strip()
                        product_status_text = (get_cell(row, 'product_status') or '').strip()
                        status_map = {'启用': 'enabled', '留用': 'retained', '弃用': 'discarded'}
                        product_status = status_map.get(product_status_text, (product_status_text or 'enabled').lower())
                        if product_status not in ('enabled', 'retained', 'discarded'):
                            product_status = 'enabled'
                        parent_code = (get_cell(row, 'parent_code') or '').strip() or None
                        parent_sku_marker = (get_cell(row, 'parent_sku_marker') or '').strip() or None
                        child_code = (get_cell(row, 'child_code') or '').strip() or None
                        dachene_yuncang_no = (get_cell(row, 'dachene_yuncang_no') or '').strip() or None
                        sku_family_name = (get_cell(row, 'sku_family') or '').strip() or None
                        fabric = (get_cell(row, 'fabric') or '').strip()
                        spec_name = (get_cell(row, 'spec_name') or '').strip()
                        sale_price_usd = self._parse_float(get_cell(row, 'sale_price_usd'))
                        package_length_in = self._parse_float(get_cell(row, 'package_length_in'))
                        package_width_in = self._parse_float(get_cell(row, 'package_width_in'))
                        package_height_in = self._parse_float(get_cell(row, 'package_height_in'))
                        net_weight_lbs = self._parse_float(get_cell(row, 'net_weight_lbs'))
                        gross_weight_lbs = self._parse_float(get_cell(row, 'gross_weight_lbs'))
                        order_sku_links = (get_cell(row, 'order_sku_links') or '').strip()

                        shop_name_text = (get_cell(row, 'shop_name') or '').strip()
                        if not shop_name_text:
                            errors.append({'row': row_idx, 'error': 'Missing shop_name'})
                            continue
                        shop_id_from_file = shop_map.get(shop_name_text)
                        if not shop_id_from_file:
                            errors.append({'row': row_idx, 'error': f'Unknown shop_name: {shop_name_text}'})
                            continue

                        parent_row = None
                        parent_id = None
                        if parent_code:
                            parent_row = parent_map.get(parent_code)
                            if not parent_row:
                                if preview_mode:
                                    parent_row = {'id': None, 'parent_code': parent_code, 'shop_id': shop_id_from_file}
                                    parent_map[parent_code] = parent_row
                                else:
                                    row_cur.execute(
                                        """
                                        INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                        VALUES (%s, %s, %s)
                                        """,
                                        (parent_code, shop_id_from_file, parent_sku_marker)
                                    )
                                    new_parent_id = row_cur.lastrowid
                                    parent_row = {'id': new_parent_id, 'parent_code': parent_code, 'shop_id': shop_id_from_file}
                                    parent_map[parent_code] = parent_row

                            shop_id = parent_row.get('shop_id')
                            if not shop_id:
                                if (not preview_mode) and parent_row.get('id'):
                                    row_cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_from_file, parent_row['id']))
                                shop_id = shop_id_from_file
                                parent_row['shop_id'] = shop_id
                            elif int(shop_id) != int(shop_id_from_file):
                                errors.append({'row': row_idx, 'error': f'Parent/shop mismatch: {parent_code} -> {shop_name_text}'})
                                continue

                            parent_id = parent_row.get('id')
                        else:
                            shop_id = shop_id_from_file

                        link_entries = []
                        for sku, qty in parse_links(order_sku_links):
                            order_id = order_map.get(sku)
                            if not order_id:
                                errors.append({'row': row_idx, 'error': f'Unknown order SKU: {sku}'})
                                link_entries = []
                                break
                            link_entries.append({'order_product_id': order_id, 'quantity': qty})
                        if not link_entries:
                            errors.append({'row': row_idx, 'error': 'Missing order_sku_links'})
                            continue

                        agg = aggregate_order_links(link_entries)
                        sku_family_id = sku_family_map.get(sku_family_name) if sku_family_name else agg.get('sku_family_id')
                        if sku_family_name and not sku_family_id:
                            errors.append({'row': row_idx, 'error': f'Unknown sku_family: {sku_family_name}'})
                            continue
                        if not sku_family_id:
                            errors.append({'row': row_idx, 'error': '无法根据订单SKU推断归属货号'})
                            continue

                        auto_fabric = agg.get('auto_fabric') or ''
                        auto_spec_name = agg.get('auto_spec_name') or ''
                        auto_platform_sku = ''
                        sku_family_code = sku_family_code_map.get(sku_family_id) or ''
                        if sku_family_code and auto_fabric and auto_spec_name:
                            auto_platform_sku = self._build_sales_platform_sku(sku_family_code, auto_spec_name, agg.get('first_fabric_code') or '')

                        final_fabric = fabric or auto_fabric
                        final_spec_name = spec_name or auto_spec_name
                        final_platform_sku = platform_sku or auto_platform_sku

                        if not final_platform_sku:
                            errors.append({'row': row_idx, 'error': 'Platform SKU missing'})
                            continue

                        new_link_sig = link_signature(link_entries)
                        old_link_sig = existing_link_map.get(final_platform_sku, tuple())
                        if preview_mode:
                            if sales_map.get(final_platform_sku):
                                updated += 1
                            else:
                                created += 1
                                sales_map[final_platform_sku] = -1
                            continue

                        try:
                            target_id = sales_map.get(final_platform_sku)
                            payload = (
                                shop_id, final_platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no, final_fabric, final_spec_name,
                                sale_price_usd, agg.get('warehouse_cost_usd'), agg.get('last_mile_cost_usd'),
                                package_length_in if package_length_in is not None else agg.get('package_length_in'),
                                package_width_in if package_width_in is not None else agg.get('package_width_in'),
                                package_height_in if package_height_in is not None else agg.get('package_height_in'),
                                net_weight_lbs if net_weight_lbs is not None else agg.get('net_weight_lbs'),
                                gross_weight_lbs if gross_weight_lbs is not None else agg.get('gross_weight_lbs')
                            )
                            
                            new_link_sig = link_signature(link_entries)
                            old_link_sig = existing_link_map.get(final_platform_sku, tuple())
                            
                            if target_id:
                                # 更新现有产品：加入批处理队列
                                batch_updates.append(payload + (target_id,))
                                updated += 1
                            else:
                                # 插入新产品：加入批处理队列
                                batch_inserts.append(payload)
                                batch_insert_skus.append(final_platform_sku)
                                created += 1
                            
                            # 记录关联链接需要的操作（延迟到 flush 后处理）
                            if (not target_id) or (new_link_sig != old_link_sig):
                                batch_links.append((final_platform_sku, target_id, new_link_sig, old_link_sig, link_entries))
                            
                            existing_link_map[final_platform_sku] = new_link_sig
                            
                            # 定期flush批处理
                            if len(batch_updates) + len(batch_inserts) >= batch_flush_size:
                                flush_batch_writes(row_cur)
                                    
                        except Exception as e:
                            errors.append({'row': row_idx, 'error': str(e)})

                    # 循环结束后，flush最后的batch（必须在游标上下文内执行）
                    if batch_updates or batch_inserts:
                        flush_batch_writes(row_cur)
                
                # 对所有新插入的产品重新查询获得ID映射
                if all_new_insert_skus and not preview_mode:
                    with conn.cursor() as cur:
                        # 去重后再查询，避免重复 SKU 的多次查询
                        unique_skus = list(set(all_new_insert_skus))
                        if unique_skus:
                            cur.execute("SELECT id, platform_sku FROM sales_products WHERE platform_sku IN ({})".format(
                                ','.join(['%s'] * len(unique_skus))
                            ), unique_skus)
                            for row in cur.fetchall() or []:
                                sales_map[row['platform_sku']] = row['id']
                
                # 批量处理所有关联链接
                for platform_sku, target_id, new_link_sig, old_link_sig, link_entries in batch_links:
                    try:
                        final_id = target_id or sales_map.get(platform_sku)
                        if not final_id:
                            # 如果是新插入的产品但查询失败，记录为错误
                            if not target_id:
                                errors.append({'error': f'关联链接处理失败 {platform_sku}: 新产品ID查询失败，无法获得product_id'})
                            continue
                        
                        if target_id:
                            relation_deleted += len(old_link_sig)
                        relation_created += len(new_link_sig)
                        self._replace_sales_order_links(conn, final_id, link_entries)
                    except Exception as e:
                        errors.append({'error': f'关联链接处理失败 {platform_sku}: {str(e)}'})

                if tx_enabled:
                    conn.commit()
                    conn.autocommit(True)

            return self.send_json({
                'status': 'success',
                'preview': 1 if preview_mode else 0,
                'total_rows': total_rows,
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'relation_created': relation_created,
                'relation_added': relation_created,
                'relation_deleted': relation_deleted,
                'errors': errors
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_api(self, environ, method, start_response):
        """销售产品管理 API（CRUD）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            def limited_text(value, max_len):
                text = (value or '').strip()
                if not text:
                    return None
                if len(text) > max_len:
                    raise ValueError(f'文本长度超限（>{max_len}）')
                return text

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                include_links = str((query_params.get('include_links', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if item_id:
                            base_sql = """
                                SELECT
                                    sp.id, COALESCE(p.shop_id, sp.shop_id) AS shop_id,
                                    sp.platform_sku, sp.product_status, sp.sku_family_id, pf.sku_family, sp.parent_id, sp.child_code, sp.dachene_yuncang_no,
                                    sp.fabric, sp.spec_name,
                                    sp.sale_price_usd, sp.warehouse_cost_usd, sp.last_mile_cost_usd,
                                    sp.package_length_in, sp.package_width_in, sp.package_height_in,
                                    sp.net_weight_lbs, sp.gross_weight_lbs,
                                    sp.created_at, sp.updated_at,
                                    s.shop_name, pt.name AS platform_type_name, b.name AS brand_name,
                                    p.parent_code
                                FROM sales_products sp
                                LEFT JOIN sales_parents p ON p.id = sp.parent_id
                                LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                                LEFT JOIN shops s ON s.id = COALESCE(p.shop_id, sp.shop_id)
                                LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                                LEFT JOIN brands b ON b.id = s.brand_id
                            """
                        else:
                            base_sql = """
                                SELECT
                                    sp.id, sp.platform_sku, sp.product_status, sp.sku_family_id, pf.sku_family,
                                    sp.child_code, sp.dachene_yuncang_no,
                                    sp.fabric, sp.spec_name,
                                    sp.sale_price_usd, sp.warehouse_cost_usd, sp.last_mile_cost_usd,
                                    sp.created_at,
                                    p.parent_code
                                FROM sales_products sp
                                LEFT JOIN sales_parents p ON p.id = sp.parent_id
                                LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                            """
                        filters = []
                        params = []
                        if item_id:
                            filters.append("sp.id = %s")
                            params.append(item_id)
                        if keyword:
                            if item_id:
                                filters.append("(sp.platform_sku LIKE %s OR s.shop_name LIKE %s OR p.parent_code LIKE %s OR sp.child_code LIKE %s OR sp.dachene_yuncang_no LIKE %s OR pf.sku_family LIKE %s)")
                                params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                            else:
                                filters.append("(sp.platform_sku LIKE %s OR p.parent_code LIKE %s OR sp.child_code LIKE %s OR sp.dachene_yuncang_no LIKE %s OR pf.sku_family LIKE %s)")
                                params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                        cur.execute(base_sql + where_sql + " ORDER BY sp.id DESC", params)
                        rows = cur.fetchall() or []
                if include_links and rows:
                    row_ids = [int(row['id']) for row in rows if row.get('id')]
                    link_map = {row_id: [] for row_id in row_ids}
                    if row_ids:
                        placeholders = ','.join(['%s'] * len(row_ids))
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    f"""
                                    SELECT spol.sales_product_id, op.id AS order_product_id, op.sku, spol.quantity
                                    FROM sales_product_order_links spol
                                    JOIN order_products op ON op.id = spol.order_product_id
                                    WHERE spol.sales_product_id IN ({placeholders})
                                    ORDER BY spol.sales_product_id ASC, op.id ASC
                                    """,
                                    row_ids
                                )
                                for rel in (cur.fetchall() or []):
                                    sales_product_id = int(rel.get('sales_product_id'))
                                    if sales_product_id not in link_map:
                                        link_map[sales_product_id] = []
                                    link_map[sales_product_id].append({
                                        'order_product_id': int(rel.get('order_product_id')),
                                        'sku': rel.get('sku') or '',
                                        'quantity': int(rel.get('quantity') or 1)
                                    })
                    for row in rows:
                        row['order_sku_links'] = link_map.get(int(row.get('id') or 0), [])
                elif item_id:
                    for row in rows:
                        row['order_sku_links'] = []

                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                product_status = (data.get('product_status') or 'enabled').strip().lower()
                if product_status not in ('enabled', 'retained', 'discarded'):
                    product_status = 'enabled'
                sku_family_id_input = self._parse_int(data.get('sku_family_id'))
                shop_id_input = self._parse_int(data.get('shop_id'))
                parent_code = (data.get('parent_code') or '').strip() or None
                parent_sku_marker = (data.get('parent_sku_marker') or '').strip() or None
                child_code = (data.get('child_code') or '').strip() or None
                dachene_yuncang_no = (data.get('dachene_yuncang_no') or '').strip() or None
                sale_price_usd = self._parse_float(data.get('sale_price_usd'))
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not links:
                    return self.send_json({'status': 'error', 'message': '关联下单SKU及数量为必填'}, start_response)

                with self._get_db_connection() as conn:
                    derived = self._derive_sales_cost_size(conn, links) if links else self._derive_sales_cost_size(conn, [])
                    sku_family_id = sku_family_id_input or derived.get('sku_family_id')
                    if not sku_family_id:
                        return self.send_json({'status': 'error', 'message': '无法根据下单SKU推断归属货号'}, start_response)

                    sku_family_code = ''
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                        sku_row = cur.fetchone()
                        if sku_row:
                            sku_family_code = (sku_row.get('sku_family') or '').strip()

                    parent_id = None
                    parent_shop_id = None
                    if parent_code:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, shop_id FROM sales_parents WHERE parent_code=%s", (parent_code,))
                            row = cur.fetchone()
                            if row:
                                parent_id = row['id']
                                parent_shop_id = row.get('shop_id')
                                if (not parent_shop_id) and shop_id_input:
                                    cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_input, parent_id))
                                    parent_shop_id = shop_id_input
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                    VALUES (%s, %s, %s)
                                    """,
                                    (parent_code, shop_id_input, parent_sku_marker)
                                )
                                parent_id = cur.lastrowid
                                parent_shop_id = shop_id_input
                    final_shop_id = parent_shop_id if parent_id else shop_id_input
                    if not final_shop_id:
                        return self.send_json({'status': 'error', 'message': 'Missing required field: shop_id'}, start_response)

                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    final_fabric = (data.get('fabric') or '').strip() or auto_fabric
                    final_spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    if manual_platform_sku:
                        platform_sku = platform_sku_manual
                    else:
                        platform_sku = auto_platform_sku or self._build_sales_platform_sku(sku_family_code, final_spec_name, final_fabric)
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)
                    
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_products
                            (shop_id, platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no, fabric, spec_name,
                             sale_price_usd, warehouse_cost_usd, last_mile_cost_usd,
                             package_length_in, package_width_in, package_height_in,
                             net_weight_lbs, gross_weight_lbs)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                                    %s, %s, %s,
                                    %s, %s, %s,
                                    %s, %s)
                            """,
                            (
                                final_shop_id, platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no, final_fabric, final_spec_name,
                                sale_price_usd, derived.get('warehouse_cost_usd'), derived.get('last_mile_cost_usd'),
                                derived.get('package_length_in'),
                                derived.get('package_width_in'),
                                derived.get('package_height_in'),
                                derived.get('net_weight_lbs'),
                                derived.get('gross_weight_lbs')
                            )
                        )
                        new_id = cur.lastrowid
                    self._replace_sales_order_links(conn, new_id, links)
                    self._ensure_listing_sales_variant_folder(sku_family_code, final_spec_name, final_fabric)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                product_status = (data.get('product_status') or 'enabled').strip().lower()
                if product_status not in ('enabled', 'retained', 'discarded'):
                    product_status = 'enabled'
                sku_family_id_input = self._parse_int(data.get('sku_family_id'))
                shop_id_input = self._parse_int(data.get('shop_id'))
                parent_code = (data.get('parent_code') or '').strip() or None
                parent_sku_marker = (data.get('parent_sku_marker') or '').strip() or None
                child_code = (data.get('child_code') or '').strip() or None
                dachene_yuncang_no = (data.get('dachene_yuncang_no') or '').strip() or None
                sale_price_usd = self._parse_float(data.get('sale_price_usd'))
                confirm_new_variant_folder = bool(data.get('confirm_new_variant_folder'))
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing required field: id'}, start_response)
                if not links:
                    return self.send_json({'status': 'error', 'message': '关联下单SKU及数量为必填'}, start_response)

                with self._get_db_connection() as conn:
                    derived = self._derive_sales_cost_size(conn, links) if links else self._derive_sales_cost_size(conn, [])
                    sku_family_id = sku_family_id_input or derived.get('sku_family_id')
                    if not sku_family_id:
                        return self.send_json({'status': 'error', 'message': '无法根据下单SKU推断归属货号'}, start_response)

                    sku_family_code = ''
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                        sku_row = cur.fetchone()
                        if sku_row:
                            sku_family_code = (sku_row.get('sku_family') or '').strip()

                    parent_id = None
                    parent_shop_id = None
                    if parent_code:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, shop_id FROM sales_parents WHERE parent_code=%s", (parent_code,))
                            row = cur.fetchone()
                            if row:
                                parent_id = row['id']
                                parent_shop_id = row.get('shop_id')
                                if (not parent_shop_id) and shop_id_input:
                                    cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_input, parent_id))
                                    parent_shop_id = shop_id_input
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                    VALUES (%s, %s, %s)
                                    """,
                                    (parent_code, shop_id_input, parent_sku_marker)
                                )
                                parent_id = cur.lastrowid
                                parent_shop_id = shop_id_input
                    final_shop_id = parent_shop_id if parent_id else shop_id_input
                    if not final_shop_id:
                        return self.send_json({'status': 'error', 'message': 'Missing required field: shop_id'}, start_response)

                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    final_fabric = (data.get('fabric') or '').strip() or auto_fabric
                    final_spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    if manual_platform_sku:
                        platform_sku = platform_sku_manual
                    else:
                        platform_sku = auto_platform_sku or self._build_sales_platform_sku(sku_family_code, final_spec_name, final_fabric)
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)

                    with conn.cursor() as cur:
                        cur.execute("SELECT spec_name, fabric FROM sales_products WHERE id=%s", (item_id,))
                        current_row = cur.fetchone() or {}
                    old_spec_name = (current_row.get('spec_name') or '').strip()
                    old_fabric = (current_row.get('fabric') or '').strip()
                    spec_or_fabric_changed = (old_spec_name != (final_spec_name or '').strip()) or (old_fabric != (final_fabric or '').strip())
                    if spec_or_fabric_changed and not confirm_new_variant_folder:
                        return self.send_json({'status': 'error', 'message': '修改规格名称或面料将新建主图文件夹，请二次确认后重试'}, start_response)
                    
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE sales_products
                            SET shop_id=%s,
                                platform_sku=%s, product_status=%s, sku_family_id=%s, parent_id=%s, child_code=%s,
                                dachene_yuncang_no=%s,
                                fabric=%s, spec_name=%s,
                                sale_price_usd=%s,
                                warehouse_cost_usd=%s,
                                last_mile_cost_usd=%s,
                                package_length_in=%s,
                                package_width_in=%s,
                                package_height_in=%s,
                                net_weight_lbs=%s,
                                gross_weight_lbs=%s
                            WHERE id=%s
                            """,
                            (
                                final_shop_id, platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no,
                                final_fabric, final_spec_name,
                                sale_price_usd,
                                derived.get('warehouse_cost_usd'),
                                derived.get('last_mile_cost_usd'),
                                derived.get('package_length_in'),
                                derived.get('package_width_in'),
                                derived.get('package_height_in'),
                                derived.get('net_weight_lbs'),
                                derived.get('gross_weight_lbs'),
                                item_id
                            )
                        )
                    self._replace_sales_order_links(conn, item_id, links)
                    if spec_or_fabric_changed:
                        self._ensure_listing_sales_variant_folder(sku_family_code, final_spec_name, final_fabric)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'PATCH':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                product_status = (data.get('product_status') or '').strip().lower()
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                if product_status not in ('enabled', 'retained', 'discarded'):
                    return self.send_json({'status': 'error', 'message': 'Invalid product_status'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE sales_products SET product_status=%s WHERE id=%s AND product_status<>%s", (product_status, item_id, product_status))
                        changed = int(cur.rowcount or 0)
                return self.send_json({'status': 'success', 'changed': changed}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_products WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '销售平台SKU已存在或关联数据无效'}, start_response)
            print("Sales product API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _ensure_listing_sales_variant_folder(self, sku_family, spec_name, fabric_code):
        sku_name = (sku_family or '').strip()
        if not sku_name:
            return
        self._ensure_listing_sku_folder(sku_name)
        base_folder = self._ensure_listing_folder()
        sku_folder = os.path.join(base_folder, self._safe_fsencode(sku_name))
        main_folder = os.path.join(sku_folder, self._safe_fsencode('主图'))
        if not os.path.exists(main_folder):
            os.makedirs(main_folder, exist_ok=True)

        spec_part = (spec_name or '').strip().replace('/', '-').replace('\\', '-')
        fabric_part = self._code_before_dash(fabric_code).replace('/', '-').replace('\\', '-')
        if not (spec_part and fabric_part):
            return
        variant_folder_name = f"{spec_part}-{fabric_part}"
        variant_folder = os.path.join(main_folder, self._safe_fsencode(variant_folder_name))
        if not os.path.exists(variant_folder):
            os.makedirs(variant_folder, exist_ok=True)

    def _get_sales_product_image_assets_folder(self):
        folder = self._join_resources('『销售产品图片』/assets')
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _sha256_hex(self, data_bytes):
        return hashlib.sha256(data_bytes or b'').hexdigest()

    def _guess_image_ext(self, filename, content):
        ext = os.path.splitext(os.path.basename(filename or ''))[1].lower()
        if ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff'):
            return ext
        if content.startswith(b'\xff\xd8\xff'):
            return '.jpg'
        if content.startswith(b'\x89PNG'):
            return '.png'
        if content.startswith(b'GIF8'):
            return '.gif'
        if content.startswith(b'RIFF') and b'WEBP' in content[:16]:
            return '.webp'
        return '.jpg'

    def _get_image_type_id_by_name(self, conn, type_name):
        name = (type_name or '').strip()
        if not name:
            name = '图文卖点'
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM image_types WHERE name=%s AND is_enabled=1 LIMIT 1", (name,))
            row = cur.fetchone() or {}
        return self._parse_int(row.get('id'))

    def _get_sales_product_image_sort_start(self, conn, sales_product_id):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM sku_image_mappings WHERE sales_product_id=%s",
                (sales_product_id,)
            )
            row = cur.fetchone() or {}
        return max(0, self._parse_int(row.get('max_sort')) or 0)

    def _find_image_asset_by_sha256(self, conn, sha256):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM image_assets WHERE sha256=%s LIMIT 1",
                (sha256,)
            )
            return cur.fetchone() or None

    def _save_image_asset_file(self, storage_path, content):
        abs_path = self._join_resources(storage_path)
        folder = os.path.dirname(abs_path)
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        with open(abs_path, 'wb') as f:
            f.write(content or b'')
        return abs_path

    def _read_sales_product_image_items(self, conn, sales_product_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sim.id AS mapping_id, sim.sort_order, sim.image_type_id,
                       ia.id AS image_asset_id, ia.sha256, ia.storage_path, ia.original_filename,
                       ia.file_ext, ia.mime_type, ia.file_size, ia.description,
                       it.name AS image_type_name
                FROM sku_image_mappings sim
                JOIN image_assets ia ON ia.id = sim.image_asset_id
                JOIN image_types it ON it.id = sim.image_type_id
                WHERE sim.sales_product_id=%s
                ORDER BY sim.sort_order ASC, sim.id ASC
                """,
                (sales_product_id,)
            )
            rows = cur.fetchall() or []
        items = []
        for row in rows:
            storage_path = (row.get('storage_path') or '').strip()
            image_name = (row.get('original_filename') or '').strip() or os.path.basename(storage_path)
            rel_bytes = os.fsencode(storage_path) if isinstance(storage_path, str) else storage_path
            image_b64 = base64.b64encode(rel_bytes).decode('ascii') if rel_bytes else ''
            items.append({
                'mapping_id': row.get('mapping_id'),
                'image_asset_id': row.get('image_asset_id'),
                'image_name': image_name,
                'image_b64': image_b64,
                'description': row.get('description') or '',
                'image_type_id': row.get('image_type_id'),
                'image_type_name': row.get('image_type_name') or '',
                'sort_order': row.get('sort_order') or 0,
                'sha256': row.get('sha256') or '',
                'file_size': row.get('file_size') or 0,
            })
        return items

    def _resolve_sales_product_variant_folder(self, sales_product_id, ensure_folder=False):
        if not sales_product_id:
            raise RuntimeError('Missing sales_product_id')
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sp.id, sp.spec_name, sp.fabric, pf.sku_family
                    FROM sales_products sp
                    LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                    WHERE sp.id=%s
                    """,
                    (sales_product_id,)
                )
                row = cur.fetchone() or {}

        if not row.get('id'):
            raise RuntimeError('销售产品不存在')

        sku_name = (row.get('sku_family') or '').strip()
        spec_part = (row.get('spec_name') or '').strip().replace('/', '-').replace('\\', '-')
        fabric_part = self._code_before_dash(row.get('fabric')).replace('/', '-').replace('\\', '-')
        if not (sku_name and spec_part and fabric_part):
            raise RuntimeError('当前销售产品缺少货号/规格/面料，无法定位主图文件夹')

        if ensure_folder:
            self._ensure_listing_sales_variant_folder(sku_name, spec_part, fabric_part)
        base_folder = self._ensure_listing_folder()
        variant_folder_name = f"{spec_part}-{fabric_part}"
        folder_path = os.path.join(
            base_folder,
            self._safe_fsencode(sku_name),
            self._safe_fsencode('主图'),
            self._safe_fsencode(variant_folder_name)
        )
        return {
            'sales_product_id': int(row.get('id')),
            'sku_family': sku_name,
            'spec_name': spec_part,
            'fabric_code': fabric_part,
            'variant_folder': variant_folder_name,
            'folder_path': folder_path,
        }

    def handle_sales_product_main_images_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query_params = parse_qs(environ.get('QUERY_STRING', ''))
                sales_product_id = self._parse_int(query_params.get('sales_product_id', [''])[0] or query_params.get('id', [''])[0])
                if not sales_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)

                with self._get_db_connection() as conn:
                    items = self._read_sales_product_image_items(conn, sales_product_id)
                    folder_info = self._resolve_sales_product_variant_folder(sales_product_id, ensure_folder=True)

                return self.send_json({
                    'status': 'success',
                    'items': items,
                    'folder': {
                        'sku_family': folder_info.get('sku_family') or '',
                        'variant_folder': folder_info.get('variant_folder') or ''
                    }
                }, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                sales_product_id = self._parse_int(data.get('sales_product_id'))
                image_name = str(data.get('image_name') or '').strip()
                description = str(data.get('description') or '').strip()
                image_type_name = str(data.get('image_type_name') or '').strip()
                sort_order = self._parse_int(data.get('sort_order'))
                if not sales_product_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id or image_name'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT sim.id, sim.image_asset_id, sim.sort_order, ia.storage_path, ia.original_filename
                            FROM sku_image_mappings sim
                            JOIN image_assets ia ON ia.id = sim.image_asset_id
                            WHERE sim.sales_product_id=%s AND (ia.original_filename=%s OR ia.storage_path=%s OR ia.storage_path LIKE %s)
                            ORDER BY sim.sort_order ASC, sim.id ASC
                            LIMIT 1
                            """,
                            (sales_product_id, image_name, image_name, f'%/{image_name}')
                        )
                        mapping = cur.fetchone() or {}
                        if not mapping.get('id'):
                            return self.send_json({'status': 'error', 'message': '图片不存在'}, start_response)

                        updates = []
                        params = []
                        if description is not None:
                            updates.append('description=%s')
                            params.append(description)
                        if image_type_name:
                            image_type_id = self._get_image_type_id_by_name(conn, image_type_name)
                            if image_type_id:
                                updates.append('image_type_id=%s')
                                params.append(image_type_id)
                        if sort_order is not None:
                            updates.append('sort_order=%s')
                            params.append(max(1, sort_order))

                        if updates:
                            if description != '':
                                cur.execute(
                                    f"UPDATE image_assets SET description=%s WHERE id=%s",
                                    (description, mapping.get('image_asset_id'))
                                )
                            if len(updates) > 1 or (updates and updates[0] != 'description=%s'):
                                cur.execute(
                                    f"UPDATE sku_image_mappings SET {', '.join(updates)} WHERE id=%s",
                                    tuple(params + [mapping.get('id')])
                                )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                sales_product_id = self._parse_int(data.get('sales_product_id'))
                image_name = str(data.get('image_name') or '').strip()
                if not sales_product_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id or image_name'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT sim.id, sim.image_asset_id, ia.storage_path
                            FROM sku_image_mappings sim
                            JOIN image_assets ia ON ia.id = sim.image_asset_id
                            WHERE sim.sales_product_id=%s AND (ia.original_filename=%s OR ia.storage_path=%s OR ia.storage_path LIKE %s)
                            ORDER BY sim.sort_order ASC, sim.id ASC
                            LIMIT 1
                            """,
                            (sales_product_id, image_name, image_name, f'%/{image_name}')
                        )
                        mapping = cur.fetchone() or {}
                        if not mapping.get('id'):
                            return self.send_json({'status': 'error', 'message': '图片文件不存在'}, start_response)
                        image_asset_id = mapping.get('image_asset_id')
                        cur.execute("DELETE FROM sku_image_mappings WHERE id=%s", (mapping.get('id'),))
                        cur.execute("SELECT COUNT(*) AS cnt FROM sku_image_mappings WHERE image_asset_id=%s", (image_asset_id,))
                        remain = self._parse_int((cur.fetchone() or {}).get('cnt')) or 0
                        if remain <= 0:
                            cur.execute("SELECT storage_path FROM image_assets WHERE id=%s", (image_asset_id,))
                            asset_row = cur.fetchone() or {}
                            storage_path = (asset_row.get('storage_path') or '').strip()
                            if storage_path:
                                try:
                                    abs_path = self._join_resources(storage_path)
                                    if os.path.exists(abs_path):
                                        os.remove(abs_path)
                                except Exception:
                                    pass
                            cur.execute("DELETE FROM image_assets WHERE id=%s", (image_asset_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_main_images_upload_api(self, environ, start_response):
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            check_only = str((query_params.get('check_only', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
            allow_duplicate = str((query_params.get('allow_duplicate', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)

            sales_product_id = self._parse_int((form.getfirst('sales_product_id', '') or '').strip())
            if not sales_product_id:
                return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)

            image_type_name = (form.getfirst('image_type_name', '') or '').strip() or '图文卖点'

            uploads = []
            for p in getattr(form, 'list', []) or []:
                if getattr(p, 'filename', None):
                    try:
                        content = p.file.read() or b''
                    except Exception:
                        content = b''
                    uploads.append({'filename': p.filename, 'content': content})
            if not uploads:
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded'}, start_response)

            with self._get_db_connection() as conn:
                image_type_id = self._get_image_type_id_by_name(conn, image_type_name)
                if not image_type_id:
                    return self.send_json({'status': 'error', 'message': f'未知图片类型: {image_type_name}'}, start_response)

                duplicates = []
                normalized = []
                for item in uploads:
                    filename = os.path.basename(item.get('filename') or '')
                    content = item.get('content') or b''
                    if not filename or not content or not self._is_image_name(filename):
                        continue
                    sha256 = self._sha256_hex(content)
                    asset = self._find_image_asset_by_sha256(conn, sha256)
                    normalized.append({
                        'filename': filename,
                        'content': content,
                        'sha256': sha256,
                        'asset': asset,
                    })
                    if asset:
                        duplicates.append({
                            'filename': filename,
                            'sha256': sha256,
                            'image_asset_id': asset.get('id'),
                            'storage_path': asset.get('storage_path') or '',
                            'description': asset.get('description') or ''
                        })

                if check_only:
                    return self.send_json({
                        'status': 'success',
                        'duplicate_count': len(duplicates),
                        'duplicates': duplicates,
                        'file_count': len(normalized)
                    }, start_response)

                if duplicates and not allow_duplicate:
                    return self.send_json({
                        'status': 'duplicate',
                        'message': '检测到重复图片，请确认是否复用已有图片',
                        'duplicate_count': len(duplicates),
                        'duplicates': duplicates,
                        'file_count': len(normalized)
                    }, start_response)

                start_sort = self._get_sales_product_image_sort_start(conn, sales_product_id)
                created_assets = 0
                reused_assets = 0
                linked = 0
                results = []
                asset_folder = self._get_sales_product_image_assets_folder()

                for idx, item in enumerate(normalized, start=1):
                    filename = item['filename']
                    content = item['content']
                    sha256 = item['sha256']
                    asset = item['asset']
                    ext = self._guess_image_ext(filename, content)
                    if asset:
                        asset_id = asset.get('id')
                        reused_assets += 1
                    else:
                        storage_name = f'{sha256}{ext}'
                        storage_path = os.path.join('『销售产品图片』', 'assets', storage_name).replace('\\', '/')
                        abs_path = self._join_resources(storage_path)
                        if not os.path.exists(abs_path):
                            self._save_image_asset_file(storage_path, content)
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO image_assets
                                (sha256, storage_path, original_filename, file_ext, mime_type, file_size, description)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                                """,
                                (
                                    sha256,
                                    storage_path,
                                    filename,
                                    ext,
                                    'image/*',
                                    len(content),
                                    ''
                                )
                            )
                            asset_id = cur.lastrowid
                        created_assets += 1

                    sort_order = start_sort + idx
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO sku_image_mappings
                                (sales_product_id, image_asset_id, image_type_id, sort_order)
                                VALUES (%s, %s, %s, %s)
                                ON DUPLICATE KEY UPDATE image_type_id=VALUES(image_type_id), sort_order=VALUES(sort_order)
                                """,
                                (sales_product_id, asset_id, image_type_id, sort_order)
                            )
                            linked += 1
                    except Exception:
                        pass
                    results.append({
                        'filename': filename,
                        'sha256': sha256,
                        'image_asset_id': asset_id,
                        'sort_order': sort_order,
                    })

                return self.send_json({
                    'status': 'success',
                    'files': [x['filename'] for x in results],
                    'created_assets': created_assets,
                    'reused_assets': reused_assets,
                    'linked': linked,
                    'duplicates': duplicates
                }, start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_api(self, environ, method, start_response):
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            def _resolve_sales_product_id(conn, value):
                item_id = self._parse_int(value)
                if item_id:
                    return item_id
                sku = str(value or '').strip()
                if not sku:
                    return None
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM sales_products WHERE platform_sku=%s LIMIT 1", (sku,))
                    row = cur.fetchone() or {}
                return self._parse_int(row.get('id'))

            def _normalize_date_text(value):
                if value is None:
                    return ''
                if isinstance(value, datetime):
                    return value.strftime('%Y-%m-%d')
                text = str(value).strip()
                if not text:
                    return ''
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return text[:10]

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                limit = min(1000, max(1, self._parse_int((query_params.get('limit', ['500'])[0] or '500')) or 500))
                sql = """
                    SELECT spp.*, sp.platform_sku, sp.sku_family_id, pf.sku_family
                    FROM sales_product_performances spp
                    JOIN sales_products sp ON sp.id = spp.sales_product_id
                    LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                """
                params = []
                filters = []
                if item_id:
                    filters.append('spp.id=%s')
                    params.append(item_id)
                if keyword:
                    like_kw = f'%{keyword}%'
                    filters.append('(sp.platform_sku LIKE %s OR pf.sku_family LIKE %s)')
                    params.extend([like_kw, like_kw])
                if filters:
                    sql += ' WHERE ' + ' AND '.join(filters)
                sql += ' ORDER BY spp.record_date DESC, spp.id DESC LIMIT %s'
                params.append(limit)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql, params)
                        rows = cur.fetchall() or []
                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method in ('POST', 'PUT'):
                data = self._read_json_body(environ)
                performance_id = self._parse_int(data.get('id'))
                sales_product_ref = data.get('sales_product_id') or data.get('platform_sku')
                record_date = _normalize_date_text(data.get('record_date'))
                if not record_date:
                    return self.send_json({'status': 'error', 'message': 'Missing record_date'}, start_response)

                with self._get_db_connection() as conn:
                    sales_product_id = _resolve_sales_product_id(conn, sales_product_ref)
                    if not sales_product_id:
                        return self.send_json({'status': 'error', 'message': '无法根据销售平台SKU找到销售产品'}, start_response)

                    values = {
                        'sales_qty': self._parse_int(data.get('sales_qty')) or 0,
                        'net_sales_amount': self._parse_float(data.get('net_sales_amount')) or 0,
                        'order_qty': self._parse_int(data.get('order_qty')) or 0,
                        'session_total': self._parse_int(data.get('session_total')) or 0,
                        'ad_impressions': self._parse_int(data.get('ad_impressions')) or 0,
                        'ad_clicks': self._parse_int(data.get('ad_clicks')) or 0,
                        'ad_orders': self._parse_int(data.get('ad_orders')) or 0,
                        'ad_spend': self._parse_float(data.get('ad_spend')) or 0,
                        'ad_sales_amount': self._parse_float(data.get('ad_sales_amount')) or 0,
                        'refund_amount': self._parse_float(data.get('refund_amount')) or 0,
                        'sub_category_rank': self._parse_int(data.get('sub_category_rank')),
                    }

                    if performance_id and method == 'PUT':
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE sales_product_performances
                                SET sales_product_id=%s, record_date=%s, sales_qty=%s, net_sales_amount=%s,
                                    order_qty=%s, session_total=%s, ad_impressions=%s, ad_clicks=%s,
                                    ad_orders=%s, ad_spend=%s, ad_sales_amount=%s, refund_amount=%s,
                                    sub_category_rank=%s
                                WHERE id=%s
                                """,
                                (
                                    sales_product_id, record_date, values['sales_qty'], values['net_sales_amount'],
                                    values['order_qty'], values['session_total'], values['ad_impressions'], values['ad_clicks'],
                                    values['ad_orders'], values['ad_spend'], values['ad_sales_amount'], values['refund_amount'],
                                    values['sub_category_rank'], performance_id
                                )
                            )
                        return self.send_json({'status': 'success', 'id': performance_id}, start_response)

                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_product_performances
                            (sales_product_id, record_date, sales_qty, net_sales_amount, order_qty, session_total,
                             ad_impressions, ad_clicks, ad_orders, ad_spend, ad_sales_amount, refund_amount, sub_category_rank)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                sales_qty=VALUES(sales_qty),
                                net_sales_amount=VALUES(net_sales_amount),
                                order_qty=VALUES(order_qty),
                                session_total=VALUES(session_total),
                                ad_impressions=VALUES(ad_impressions),
                                ad_clicks=VALUES(ad_clicks),
                                ad_orders=VALUES(ad_orders),
                                ad_spend=VALUES(ad_spend),
                                ad_sales_amount=VALUES(ad_sales_amount),
                                refund_amount=VALUES(refund_amount),
                                sub_category_rank=VALUES(sub_category_rank)
                            """,
                            (
                                sales_product_id, record_date, values['sales_qty'], values['net_sales_amount'],
                                values['order_qty'], values['session_total'], values['ad_impressions'], values['ad_clicks'],
                                values['ad_orders'], values['ad_spend'], values['ad_sales_amount'], values['refund_amount'],
                                values['sub_category_rank']
                            )
                        )
                        return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_product_performances WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT platform_sku FROM sales_products ORDER BY platform_sku")
                    sku_rows = cur.fetchall() or []
            sku_values = [str(row.get('platform_sku') or '').strip() for row in sku_rows if str(row.get('platform_sku') or '').strip()]

            wb = Workbook()
            ws = wb.active
            ws.title = 'sales_product_performance'

            headers = [
                '销售平台SKU*', '日期*', '销量*', '净销售额(USD)*', '订单量*', 'Session-Total*',
                '(广告)展示*', '(广告)点击*', '(广告)订单量*', '(广告)花费(USD)*', '(广告)销售额(USD)*',
                '退款金额(USD)*', '小类排名*'
            ]
            ws.append(headers)
            ws.append([
                sku_values[0] if sku_values else '',
                datetime.now().strftime('%Y-%m-%d'),
                12,
                999.99,
                10,
                480,
                2500,
                88,
                6,
                120.50,
                899.90,
                0.00,
                1234
            ])

            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            for cell in ws[2]:
                cell.fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
                cell.font = Font(italic=True, color='888888')

            widths = [24, 14, 10, 14, 10, 12, 12, 12, 12, 14, 14, 12, 12]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width

            options_ws = wb.create_sheet('options')
            options_ws.sheet_state = 'hidden'
            options_ws.cell(row=1, column=1, value='sales_platform_sku')
            for idx, sku in enumerate(sku_values, start=2):
                options_ws.cell(row=idx, column=1, value=sku)

            if sku_values:
                sku_validation = DataValidation(type='list', formula1=f'=options!$A$2:$A${len(sku_values) + 1}', allow_blank=False)
                ws.add_data_validation(sku_validation)
                for row_idx in range(3, 1000):
                    sku_validation.add(f'A{row_idx}')

            ws.freeze_panes = 'A3'
            return self._send_excel_workbook(wb, 'sales_product_performance_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active
            headers = [str(cell.value or '').strip() for cell in ws[1]]
            header_map = {name: idx for idx, name in enumerate(headers)}

            required = [
                '销售平台SKU*', '日期*', '销量*', '净销售额(USD)*', '订单量*', 'Session-Total*',
                '(广告)展示*', '(广告)点击*', '(广告)订单量*', '(广告)花费(USD)*', '(广告)销售额(USD)*',
                '退款金额(USD)*', '小类排名*'
            ]
            for col_name in required:
                if col_name not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {col_name}'}, start_response)

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx].value

            def normalize_date(value):
                if value is None:
                    return ''
                if isinstance(value, datetime):
                    return value.strftime('%Y-%m-%d')
                text = str(value).strip()
                if not text:
                    return ''
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return text[:10]

            def row_signature(payload):
                return '|'.join([
                    str(payload.get('sales_qty') or 0),
                    str(payload.get('net_sales_amount') or 0),
                    str(payload.get('order_qty') or 0),
                    str(payload.get('session_total') or 0),
                    str(payload.get('ad_impressions') or 0),
                    str(payload.get('ad_clicks') or 0),
                    str(payload.get('ad_orders') or 0),
                    str(payload.get('ad_spend') or 0),
                    str(payload.get('ad_sales_amount') or 0),
                    str(payload.get('refund_amount') or 0),
                    str(payload.get('sub_category_rank') or ''),
                ])

            created = 0
            updated = 0
            unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, platform_sku FROM sales_products")
                    sku_map = {str(row.get('platform_sku') or '').strip(): int(row.get('id')) for row in (cur.fetchall() or []) if str(row.get('platform_sku') or '').strip() and row.get('id')}

                    cur.execute("SELECT spp.id, spp.sales_product_id, spp.record_date, spp.sales_qty, spp.net_sales_amount, spp.order_qty, spp.session_total, spp.ad_impressions, spp.ad_clicks, spp.ad_orders, spp.ad_spend, spp.ad_sales_amount, spp.refund_amount, spp.sub_category_rank, sp.platform_sku FROM sales_product_performances spp JOIN sales_products sp ON sp.id=spp.sales_product_id")
                    existing = {}
                    for row in (cur.fetchall() or []):
                        key = (int(row.get('sales_product_id') or 0), str(row.get('record_date') or '').strip())
                        existing[key] = row

                for row_idx in range(2, ws.max_row + 1):
                    row = ws[row_idx]
                    if not any(cell.value is not None and str(cell.value).strip() for cell in row):
                        continue

                    try:
                        sku = str(get_cell(row, '销售平台SKU*') or '').strip()
                        sales_product_id = sku_map.get(sku)
                        if not sales_product_id:
                            raise ValueError(f'Unknown platform_sku: {sku}')

                        record_date = normalize_date(get_cell(row, '日期*'))
                        if not record_date:
                            raise ValueError('日期格式错误')

                        payload = {
                            'sales_product_id': sales_product_id,
                            'record_date': record_date,
                            'sales_qty': self._parse_int(get_cell(row, '销量*')) or 0,
                            'net_sales_amount': self._parse_float(get_cell(row, '净销售额(USD)*')) or 0,
                            'order_qty': self._parse_int(get_cell(row, '订单量*')) or 0,
                            'session_total': self._parse_int(get_cell(row, 'Session-Total*')) or 0,
                            'ad_impressions': self._parse_int(get_cell(row, '(广告)展示*')) or 0,
                            'ad_clicks': self._parse_int(get_cell(row, '(广告)点击*')) or 0,
                            'ad_orders': self._parse_int(get_cell(row, '(广告)订单量*')) or 0,
                            'ad_spend': self._parse_float(get_cell(row, '(广告)花费(USD)*')) or 0,
                            'ad_sales_amount': self._parse_float(get_cell(row, '(广告)销售额(USD)*')) or 0,
                            'refund_amount': self._parse_float(get_cell(row, '退款金额(USD)*')) or 0,
                            'sub_category_rank': self._parse_int(get_cell(row, '小类排名*')),
                        }
                        signature = row_signature(payload)
                        existing_row = existing.get((sales_product_id, record_date))
                        if existing_row:
                            existing_payload = {
                                'sales_qty': existing_row.get('sales_qty') or 0,
                                'net_sales_amount': existing_row.get('net_sales_amount') or 0,
                                'order_qty': existing_row.get('order_qty') or 0,
                                'session_total': existing_row.get('session_total') or 0,
                                'ad_impressions': existing_row.get('ad_impressions') or 0,
                                'ad_clicks': existing_row.get('ad_clicks') or 0,
                                'ad_orders': existing_row.get('ad_orders') or 0,
                                'ad_spend': existing_row.get('ad_spend') or 0,
                                'ad_sales_amount': existing_row.get('ad_sales_amount') or 0,
                                'refund_amount': existing_row.get('refund_amount') or 0,
                                'sub_category_rank': existing_row.get('sub_category_rank') or '',
                            }
                            if row_signature(existing_payload) == signature:
                                unchanged += 1
                            else:
                                updated += 1
                        else:
                            created += 1

                        cur.execute(
                            """
                            INSERT INTO sales_product_performances
                            (sales_product_id, record_date, sales_qty, net_sales_amount, order_qty, session_total,
                             ad_impressions, ad_clicks, ad_orders, ad_spend, ad_sales_amount, refund_amount, sub_category_rank)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                sales_qty=VALUES(sales_qty),
                                net_sales_amount=VALUES(net_sales_amount),
                                order_qty=VALUES(order_qty),
                                session_total=VALUES(session_total),
                                ad_impressions=VALUES(ad_impressions),
                                ad_clicks=VALUES(ad_clicks),
                                ad_orders=VALUES(ad_orders),
                                ad_spend=VALUES(ad_spend),
                                ad_sales_amount=VALUES(ad_sales_amount),
                                refund_amount=VALUES(refund_amount),
                                sub_category_rank=VALUES(sub_category_rank)
                            """,
                            (
                                payload['sales_product_id'], payload['record_date'], payload['sales_qty'], payload['net_sales_amount'],
                                payload['order_qty'], payload['session_total'], payload['ad_impressions'], payload['ad_clicks'],
                                payload['ad_orders'], payload['ad_spend'], payload['ad_sales_amount'], payload['refund_amount'],
                                payload['sub_category_rank']
                            )
                        )
                    except Exception as e:
                        errors.append({'row': row_idx, 'error': str(e)})

            return self.send_json({
                'status': 'success',
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'errors': errors,
                'total_rows': created + updated + unchanged + len(errors)
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _normalize_sales_order_links(self, links):
        items = []
        if not isinstance(links, list):
            return items
        qty_by_order_id = {}
        for entry in links:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not order_product_id:
                continue
            qty_by_order_id[order_product_id] = qty_by_order_id.get(order_product_id, 0) + max(1, quantity)

        for order_product_id, quantity in qty_by_order_id.items():
            items.append({'order_product_id': order_product_id, 'quantity': max(1, quantity)})
        return items

    def _replace_sales_order_links(self, conn, sales_product_id, links):
        """删除旧关联，批量插入新关联"""
        if not sales_product_id or sales_product_id < 0:
            raise ValueError(f'Invalid sales_product_id: {sales_product_id}')

        # 合并同一 order_product_id，避免复合主键 (sales_product_id, order_product_id) 重复
        merged_links = self._normalize_sales_order_links(links)
        
        with conn.cursor() as cur:
            # 先删除旧的关联
            try:
                cur.execute("DELETE FROM sales_product_order_links WHERE sales_product_id=%s", (sales_product_id,))
            except Exception as e:
                raise Exception(f'删除旧关联失败(pid={sales_product_id}): {str(e)}')
            
            if not merged_links:
                return
            
            # 用多行 INSERT VALUES 批量插入新关联（pymysql 支持）
            try:
                # 构建多行 VALUES 语句
                placeholders = ','.join(['(%s, %s, %s)'] * len(merged_links))
                insert_values = []
                for entry in merged_links:
                    insert_values.extend([sales_product_id, entry['order_product_id'], entry['quantity']])
                
                cur.execute(
                    f"""
                    INSERT INTO sales_product_order_links (sales_product_id, order_product_id, quantity)
                    VALUES {placeholders}
                    """,
                    insert_values
                )
            except Exception as e:
                # 如果批量插入失败，回退到逐行插入
                try:
                    for entry in merged_links:
                        cur.execute(
                            """
                            INSERT INTO sales_product_order_links (sales_product_id, order_product_id, quantity)
                            VALUES (%s, %s, %s)
                            """,
                            (sales_product_id, entry['order_product_id'], entry['quantity'])
                        )
                except Exception as e2:
                    raise Exception(f'关联链接批量插入失败(pid={sales_product_id}, 入: {len(merged_links)}): {str(e2)}')

    def _derive_sales_fields(self, conn, sku_family_id, links):
        if not links:
            return '', '', ''

        sku_family_code = ''
        if sku_family_id:
            with conn.cursor() as cur:
                cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                row = cur.fetchone()
                if row:
                    sku_family_code = (row.get('sku_family') or '').strip()

        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT op.id, op.sku, op.spec_qty_short, fm.fabric_code, fm.fabric_name_en
                FROM order_products op
                LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                WHERE op.id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []

        row_map = {row['id']: row for row in rows}
        fabrics = []
        spec_parts = []
        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            fabric_code = self._code_before_dash(row.get('fabric_code'))
            if not fabric_code:
                fabric_code = self._code_before_dash(row.get('fabric_name_en'))
            if fabric_code and fabric_code not in fabrics:
                fabrics.append(fabric_code)
            spec_short = (row.get('spec_qty_short') or '').strip()
            if spec_short:
                spec_parts.append(f"{entry['quantity']}{spec_short}")

        fabric = ' / '.join(fabrics)
        spec_name = ''.join(spec_parts)

        platform_sku = ''
        if sku_family_code and fabric and spec_name:
            first_fabric = fabrics[0] if fabrics else ''
            platform_sku = self._build_sales_platform_sku(sku_family_code, spec_name, first_fabric)

        return fabric, spec_name, platform_sku

    def _derive_sales_cost_size(self, conn, links):
        if not links:
            return {
                'warehouse_cost_usd': 0.0,
                'last_mile_cost_usd': 0.0,
                'package_length_in': 0.0,
                'package_width_in': 0.0,
                'package_height_in': 0.0,
                'net_weight_lbs': 0.0,
                'gross_weight_lbs': 0.0,
                'sku_family_id': None
            }

        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, sku_family_id,
                       cost_usd, last_mile_avg_freight_usd,
                       package_length_in, package_width_in, package_height_in,
                       net_weight_lbs, gross_weight_lbs
                FROM order_products
                WHERE id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []

        row_map = {row['id']: row for row in rows}
        warehouse_cost_usd = 0.0
        last_mile_cost_usd = 0.0
        package_length_in = 0.0
        package_width_in = 0.0
        package_height_in = 0.0
        net_weight_lbs = 0.0
        gross_weight_lbs = 0.0
        sku_family_id = None

        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            qty = max(1, int(entry.get('quantity') or 1))
            if sku_family_id is None:
                sku_family_id = row.get('sku_family_id')

            warehouse_cost_usd += float(row.get('cost_usd') or 0) * qty
            last_mile_cost_usd += float(row.get('last_mile_avg_freight_usd') or 0) * qty
            package_length_in = max(package_length_in, float(row.get('package_length_in') or 0))
            package_width_in = max(package_width_in, float(row.get('package_width_in') or 0))
            package_height_in = max(package_height_in, float(row.get('package_height_in') or 0))
            net_weight_lbs += float(row.get('net_weight_lbs') or 0) * qty
            gross_weight_lbs += float(row.get('gross_weight_lbs') or 0) * qty

        return {
            'warehouse_cost_usd': round(warehouse_cost_usd, 2),
            'last_mile_cost_usd': round(last_mile_cost_usd, 2),
            'package_length_in': round(package_length_in, 2),
            'package_width_in': round(package_width_in, 2),
            'package_height_in': round(package_height_in, 2),
            'net_weight_lbs': round(net_weight_lbs, 2),
            'gross_weight_lbs': round(gross_weight_lbs, 2),
            'sku_family_id': sku_family_id
        }

    def _code_before_dash(self, value):
        text = (value or '').strip()
        if not text:
            return ''
        return text.split('-', 1)[0].strip() or text

    def _build_sales_platform_sku(self, sku_family_code, spec_name, fabric_code):
        sku_part = (sku_family_code or '').strip()
        spec_part = (spec_name or '').strip()
        fabric_part = self._code_before_dash(fabric_code)
        if not (sku_part and spec_part and fabric_part):
            return ''
        return f"{sku_part}-{spec_part}-{fabric_part}"


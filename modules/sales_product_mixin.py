import re
import io
import cgi
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
            if method != 'GET':
                self._ensure_sales_parent_tables()
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
            
            self._ensure_sales_product_tables()
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

            header_row_idx = 2 if str(ws.cell(row=1, column=1).value or '').strip() == '基础信息' else 1
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
                if h:
                    h_stripped = str(h).strip()
                    field_code = label_to_code.get(h_stripped, h_stripped)
                    header_map[field_code] = idx

            def get_cell(row, key):
                idx = header_map.get(key)
                if idx is None:
                    return None
                return row[idx].value

            def parse_links(raw):
                """解析 order_sku_links：支持换行\\n、分号;、竖线|分隔，支持 *数量 或重复计数"""
                if raw is None:
                    return []
                text = str(raw).strip()
                if not text:
                    return []
                
                # 支持换行符、各类分隔符分割
                parts = [t.strip() for t in re.split(r'[\n;；|]+', text) if t.strip()]
                result = []
                sku_count = {}  # 记录每个SKU的重复计数
                
                for part in parts:
                    if '*' in part:
                        # 显式指定数量：MS01A-Brown*2
                        sku, qty = part.split('*', 1)
                    else:
                        # 未指定数量，检查是否重复出现
                        sku, qty = part, None
                    
                    sku = sku.strip()
                    if not sku:
                        continue
                    
                    if qty is None:
                        # 默认计数：重复出现同一SKU则累加
                        if sku not in sku_count:
                            sku_count[sku] = 1
                        else:
                            sku_count[sku] += 1
                        qty_val = sku_count[sku]
                    else:
                        # 显式指定的数量
                        qty = qty.strip()
                        try:
                            qty_val = int(qty) if qty else 1
                        except Exception:
                            qty_val = 1
                    
                    result.append((sku, max(1, qty_val)))
                
                return result

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

            self._ensure_sales_product_tables()
            with self._get_db_connection() as conn:
                tx_enabled = False
                batch_write_count = 0
                batch_size = 200
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
                update_sql = """
                    UPDATE sales_products
                    SET shop_id=%s,
                        platform_sku=%s,
                        product_status=%s,
                        sku_family_id=%s,
                        parent_id=%s,
                        child_code=%s,
                        dachene_yuncang_no=%s,
                        fabric=%s,
                        spec_name=%s,
                        sale_price_usd=%s,
                        warehouse_cost_usd=%s,
                        last_mile_cost_usd=%s,
                        package_length_in=%s,
                        package_width_in=%s,
                        package_height_in=%s,
                        net_weight_lbs=%s,
                        gross_weight_lbs=%s
                    WHERE id=%s
                """
                insert_sql = """
                    INSERT INTO sales_products
                        (shop_id, platform_sku, product_status, sku_family_id, parent_id, child_code, dachene_yuncang_no, fabric, spec_name,
                     sale_price_usd, warehouse_cost_usd, last_mile_cost_usd,
                     package_length_in, package_width_in, package_height_in,
                     net_weight_lbs, gross_weight_lbs)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s,
                            %s, %s)
                """
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
                            if target_id:
                                row_cur.execute(update_sql, payload + (target_id,))
                                new_id = target_id
                            else:
                                row_cur.execute(insert_sql, payload)
                                new_id = row_cur.lastrowid

                            if (not target_id) or (new_link_sig != old_link_sig):
                                if target_id:
                                    relation_deleted += len(old_link_sig)
                                relation_created += len(new_link_sig)
                                self._replace_sales_order_links(conn, new_id, link_entries)
                            existing_link_map[final_platform_sku] = new_link_sig
                            if target_id:
                                updated += 1
                            else:
                                created += 1
                                sales_map[final_platform_sku] = new_id

                            if tx_enabled:
                                batch_write_count += 1
                                if batch_write_count >= batch_size:
                                    conn.commit()
                                    batch_write_count = 0
                        except Exception as e:
                            errors.append({'row': row_idx, 'error': str(e)})

                if tx_enabled:
                    if batch_write_count > 0:
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
            if method in ('POST', 'PUT', 'DELETE'):
                self._ensure_sales_product_tables()
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

    def _normalize_sales_order_links(self, links):
        items = []
        if not isinstance(links, list):
            return items
        for entry in links:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not order_product_id:
                continue
            items.append({'order_product_id': order_product_id, 'quantity': max(1, quantity)})
        return items

    def _replace_sales_order_links(self, conn, sales_product_id, links):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sales_product_order_links WHERE sales_product_id=%s", (sales_product_id,))
        if not links:
            return
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO sales_product_order_links (sales_product_id, order_product_id, quantity)
                VALUES (%s, %s, %s)
                """,
                [(sales_product_id, entry['order_product_id'], entry['quantity']) for entry in links]
            )

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


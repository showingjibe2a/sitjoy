import io
import re
import zipfile
import xml.etree.ElementTree as ET

try:
    from openpyxl import Workbook
except Exception:
    Workbook = None


class ExcelToolsMixin:
    def _send_excel_workbook(self, workbook, filename, start_response):
        output = io.BytesIO()
        workbook.save(output)
        data = output.getvalue()
        start_response('200 OK', [
            ('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
            ('Content-Disposition', f'attachment; filename="{filename}"'),
            ('Content-Length', str(len(data)))
        ])
        return [data]


    def _sanitize_xlsx_bool_cells(self, file_bytes):
        if not file_bytes:
            return file_bytes
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return file_bytes

        out_buffer = io.BytesIO()
        changed = False
        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        valid_bool_values = {'0', '1', 'true', 'false'}

        with zin:
            with zipfile.ZipFile(out_buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    name = info.filename
                    data = zin.read(name)

                    if name.startswith('xl/worksheets/') and name.endswith('.xml'):
                        try:
                            root = ET.fromstring(data)
                            sheet_changed = False
                            for cell in root.findall('.//x:c', ns):
                                if cell.get('t') != 'b':
                                    continue
                                value_node = cell.find('x:v', ns)
                                raw_text = '' if value_node is None or value_node.text is None else str(value_node.text).strip()
                                if raw_text.lower() not in valid_bool_values:
                                    cell.set('t', 'str')
                                    if value_node is None:
                                        value_node = ET.SubElement(cell, '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v')
                                    value_node.text = raw_text
                                    sheet_changed = True
                            if sheet_changed:
                                data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
                                changed = True
                        except Exception:
                            pass

                    zout.writestr(info, data)

        if changed:
            return out_buffer.getvalue()
        return file_bytes


    def _scan_xlsx_invalid_bool_cells(self, file_bytes, max_samples=8):
        if not file_bytes:
            return {'count': 0, 'samples': []}
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return {'count': 0, 'samples': []}

        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        valid_bool_values = {'0', '1', 'true', 'false'}
        count = 0
        samples = []

        with zin:
            for name in zin.namelist():
                if not (name.startswith('xl/worksheets/') and name.endswith('.xml')):
                    continue
                try:
                    root = ET.fromstring(zin.read(name))
                except Exception:
                    continue
                for cell in root.findall('.//x:c', ns):
                    if cell.get('t') != 'b':
                        continue
                    value_node = cell.find('x:v', ns)
                    raw_text = '' if value_node is None or value_node.text is None else str(value_node.text).strip()
                    if raw_text.lower() in valid_bool_values:
                        continue
                    count += 1
                    if len(samples) < max_samples:
                        samples.append({
                            'sheet_xml': name,
                            'cell': cell.get('r') or '',
                            'value': raw_text
                        })

        return {'count': count, 'samples': samples}


    def _xlsx_cell_ref_to_rc(self, ref):
        ref_text = (ref or '').strip().upper()
        match = re.match(r'^([A-Z]+)(\d+)$', ref_text)
        if not match:
            return None, None
        letters, row_text = match.group(1), match.group(2)
        col = 0
        for ch in letters:
            col = col * 26 + (ord(ch) - ord('A') + 1)
        try:
            row = int(row_text)
        except Exception:
            return None, None
        return row, col


    def _extract_xlsx_shared_strings(self, zin):
        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        if 'xl/sharedStrings.xml' not in zin.namelist():
            return []
        try:
            root = ET.fromstring(zin.read('xl/sharedStrings.xml'))
            items = []
            for si in root.findall('.//x:si', ns):
                texts = []
                for t_node in si.findall('.//x:t', ns):
                    texts.append(t_node.text or '')
                items.append(''.join(texts))
            return items
        except Exception:
            return []


    def _rebuild_workbook_from_xlsx_xml(self, file_bytes):
        try:
            zin = zipfile.ZipFile(io.BytesIO(file_bytes), 'r')
        except Exception:
            return None

        ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        with zin:
            sheet_names = [name for name in zin.namelist() if name.startswith('xl/worksheets/') and name.endswith('.xml')]
            if not sheet_names:
                return None
            sheet_name = 'xl/worksheets/sheet1.xml' if 'xl/worksheets/sheet1.xml' in sheet_names else sorted(sheet_names)[0]
            try:
                sheet_root = ET.fromstring(zin.read(sheet_name))
            except Exception:
                return None
            shared_strings = self._extract_xlsx_shared_strings(zin)

        wb = Workbook()
        ws = wb.active

        for row_node in sheet_root.findall('.//x:sheetData/x:row', ns):
            row_index = self._parse_int(row_node.get('r')) or 1
            fallback_col = 1
            for cell_node in row_node.findall('x:c', ns):
                ref = cell_node.get('r')
                parsed_row, parsed_col = self._xlsx_cell_ref_to_rc(ref) if ref else (None, None)
                target_row = parsed_row or row_index
                target_col = parsed_col or fallback_col
                fallback_col = target_col + 1

                cell_type = (cell_node.get('t') or '').strip()
                if cell_type == 'inlineStr':
                    text_parts = []
                    for t_node in cell_node.findall('.//x:t', ns):
                        text_parts.append(t_node.text or '')
                    value = ''.join(text_parts)
                else:
                    v_node = cell_node.find('x:v', ns)
                    raw_text = '' if v_node is None or v_node.text is None else str(v_node.text)
                    if cell_type == 's':
                        idx = self._parse_int(raw_text)
                        if idx is not None and 0 <= idx < len(shared_strings):
                            value = shared_strings[idx]
                        else:
                            value = raw_text
                    elif cell_type == 'b':
                        lowered = raw_text.strip().lower()
                        if lowered in ('1', 'true'):
                            value = '1'
                        elif lowered in ('0', 'false'):
                            value = '0'
                        else:
                            value = raw_text
                    else:
                        value = raw_text

                if value != '':
                    ws.cell(row=target_row, column=target_col, value=value)

        return wb






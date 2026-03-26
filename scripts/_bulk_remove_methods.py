import ast
from pathlib import Path

path = Path('app.py')
src = path.read_text(encoding='utf-8')
mod = ast.parse(src)

TARGETS = {
    'handle_auth_api','handle_employee_api',
    '_dispatch_api_request','_validate_api_permission','_dispatch_page_request',
    'handle_logistics_factory_api','handle_logistics_forwarder_api','handle_logistics_supplier_api',
    'handle_logistics_warehouse_api','handle_logistics_warehouse_template_api','handle_logistics_warehouse_import_api',
    'handle_logistics_warehouse_inventory_api','handle_logistics_warehouse_inventory_template_api','handle_logistics_warehouse_inventory_import_api',
    'handle_logistics_warehouse_dashboard_api',
    'handle_factory_stock_api','handle_factory_stock_template_api','handle_factory_stock_import_api',
    'handle_factory_wip_api','handle_factory_wip_template_api','handle_factory_wip_import_api',
    '_calc_qty_consistent_from_items','_refresh_transit_qty_consistent',
    'handle_logistics_in_transit_api','handle_logistics_in_transit_template_api','handle_logistics_in_transit_import_api',
    'handle_logistics_in_transit_doc_upload_api','handle_logistics_in_transit_doc_files_api',
    'handle_parent_api','handle_sales_product_api','handle_sales_product_template_api','handle_sales_product_import_api',
    '_registration_parse_date','_registration_parse_item_text','_registration_parse_logistics_text',
    '_registration_save_children','_registration_fill_item_ids','_registration_fetch_detail',
    'handle_sales_order_registration_api','handle_sales_order_registration_template_api','handle_sales_order_registration_import_api'
}

wsgi_cls = None
for n in mod.body:
    if isinstance(n, ast.ClassDef) and n.name == 'WSGIApp':
        wsgi_cls = n
        break
if wsgi_cls is None:
    raise SystemExit('WSGIApp not found')

ranges = []
removed = []
for n in wsgi_cls.body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in TARGETS:
        ranges.append((n.lineno, n.end_lineno, n.name))
        removed.append(n.name)

if not ranges:
    print('No target methods found')
    raise SystemExit(0)

lines = src.splitlines(keepends=True)
for start, end, _ in sorted(ranges, key=lambda x: x[0], reverse=True):
    del lines[start-1:end]

path.write_text(''.join(lines), encoding='utf-8')
print(f'Removed methods: {len(removed)}')
print(','.join(sorted(set(removed))))

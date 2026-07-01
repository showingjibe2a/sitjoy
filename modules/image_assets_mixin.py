# -*- coding: utf-8 -*-
"""
图片资产中心（image_assets + 各实体 mapping 表）统一读写。

销售主图、面料、下单、图库关联等均应通过本 Mixin，避免各模块重复实现入库逻辑。
依赖（经 WSGIApp MRO）：SalesProductMixin 的 _storage_path_from_abs / _sha256_hex /
_insert_image_asset_dynamic / _ensure_image_asset_from_rel_path / _get_image_type_id_by_name。
"""

import base64
import os


class ImageAssetsMixin:
    """image_assets 与 fabric_image_mappings 等映射表的统一操作。"""

    # -------------------------------------------------------------------------
    # image_assets 表结构探测 / 批量 upsert
    # -------------------------------------------------------------------------

    def _image_assets_table_flags(self, conn):
        return {
            'has_tid': self._table_has_column(conn, 'image_assets', 'image_type_id'),
            'has_dep': self._table_has_column(conn, 'image_assets', 'is_deprecated'),
            'has_ofn': self._table_has_column(conn, 'image_assets', 'original_filename'),
        }

    def _image_assets_load_by_sha(self, conn, sha_list):
        existing = {}
        if not sha_list:
            return existing
        with conn.cursor() as cur:
            placeholders = ','.join(['%s'] * len(set(sha_list)))
            cur.execute(
                f"SELECT id, sha256 FROM image_assets WHERE sha256 IN ({placeholders})",
                tuple(sorted(set(sha_list))),
            )
            for r in (cur.fetchall() or []):
                existing[str(r.get('sha256') or '')] = self._parse_int(r.get('id')) or 0
        return existing

    def _image_assets_resolve_type_ids(self, conn, prepared, has_tid):
        type_id_by_name = {}
        if not has_tid:
            return type_id_by_name
        for rec in prepared:
            nm = (rec.get('type_name') or '').strip() or '文字卖点图'
            if nm not in type_id_by_name:
                try:
                    type_id_by_name[nm] = self._get_image_type_id_by_name(conn, nm)
                except Exception:
                    type_id_by_name[nm] = None
        return type_id_by_name

    def _image_assets_prepared_from_rows(self, rows, resolve_abs_path):
        """
        从 (image_name, type_name, description, sort_order) 行构建入库记录。
        resolve_abs_path: callable(image_name) -> abs_path
        """
        prepared = []
        sha_list = []
        for image_name, type_name, description, sort_order in rows:
            abs_path = resolve_abs_path(image_name)
            if not abs_path or not os.path.exists(abs_path):
                continue
            try:
                with open(abs_path, 'rb') as f:
                    content = f.read() or b''
            except Exception:
                continue
            if not content:
                continue
            sha256 = self._sha256_hex(content)
            storage_path = self._storage_path_from_abs(abs_path)
            if not storage_path:
                storage_path = str(image_name).replace('\\', '/')
            orig_fn = os.path.basename(str(image_name).strip().replace('\\', '/')) or os.path.basename(storage_path)
            prepared.append({
                'sha256': sha256,
                'storage_path': storage_path,
                'original_filename': orig_fn,
                'type_name': type_name,
                'description': (description or '')[:1000],
                'sort_order': int(sort_order),
            })
            sha_list.append(sha256)
        return prepared, sha_list

    def _image_assets_upsert_batch(self, conn, prepared, sha_list):
        """批量 upsert image_assets；返回 sha256 -> asset_id。"""
        if not prepared:
            return {}
        flags = self._image_assets_table_flags(conn)
        type_id_by_name = self._image_assets_resolve_type_ids(conn, prepared, flags['has_tid'])
        existing_by_sha = self._image_assets_load_by_sha(conn, sha_list)

        has_tid = flags['has_tid']
        has_dep = flags['has_dep']
        has_ofn = flags['has_ofn']

        cols_base = ['sha256', 'storage_path', 'description']
        if has_ofn:
            cols_base.append('original_filename')
        if has_tid:
            cols_base.append('image_type_id')
        if has_dep:
            cols_base.append('is_deprecated')
        insert_sql = f"INSERT INTO image_assets ({', '.join(cols_base)}) VALUES ({', '.join(['%s'] * len(cols_base))})"

        to_insert = []
        for rec in prepared:
            if existing_by_sha.get(rec['sha256']):
                continue
            vals = [rec['sha256'], rec['storage_path'], rec.get('description') or None]
            if has_ofn:
                vals.append(rec.get('original_filename') or '')
            if has_tid:
                vals.append(type_id_by_name.get((rec.get('type_name') or '').strip() or '文字卖点图'))
            if has_dep:
                vals.append(0)
            to_insert.append(tuple(vals))

        if to_insert:
            with conn.cursor() as cur:
                cur.executemany(insert_sql, to_insert)
            existing_by_sha = self._image_assets_load_by_sha(conn, sha_list)

        update_sets = ['description=%s']
        if has_tid:
            update_sets.append('image_type_id=%s')
        update_sql = f"UPDATE image_assets SET {', '.join(update_sets)} WHERE id=%s"
        update_rows = []
        for rec in prepared:
            aid = existing_by_sha.get(rec['sha256']) or 0
            if not aid:
                continue
            params = [rec.get('description') or None]
            if has_tid:
                params.append(type_id_by_name.get((rec.get('type_name') or '').strip() or '文字卖点图'))
            params.append(int(aid))
            update_rows.append(tuple(params))
        if update_rows:
            with conn.cursor() as cur:
                cur.executemany(update_sql, update_rows)

        return existing_by_sha

    # -------------------------------------------------------------------------
    # 面料图片：payload 解析 / UI 行 / 映射同步
    # -------------------------------------------------------------------------

    def _image_payload_rows_for_fabric(self, images, sort_base=0, append_after=None):
        """面料保存/绑定 payload → 标准行。"""
        rows = []
        for idx, item in enumerate(images or []):
            if isinstance(item, dict):
                image_name = str(item.get('image_name') or item.get('new_name') or '').strip()
                type_name = self._normalize_fabric_remark(item.get('remark') or item.get('image_type'))
                description = str(item.get('description') or '').strip()
                sort_order = self._parse_int(item.get('sort_order'))
            else:
                image_name = str(item or '').strip()
                type_name = ''
                description = ''
                sort_order = None
            if not image_name:
                continue
            if sort_order is None:
                if append_after is not None:
                    sort_order = int(append_after) + 1 + len(rows)
                else:
                    sort_order = int(sort_base) + len(rows)
            rows.append((image_name, type_name, description, int(sort_order)))
        return rows

    def _fabric_image_row_to_ui(self, row):
        """DB 行 → 面料列表/编辑弹窗通用图片项。"""
        storage_path = (row.get('storage_path') or '').strip()
        display_name = os.path.basename(storage_path) if storage_path else ''
        image_name = (row.get('original_filename') or '').strip() or display_name
        preview_b64 = ''
        if storage_path:
            parts = [p for p in storage_path.replace('\\', '/').split('/') if p]
            if parts:
                _, preview_b64 = self._resources_rel_path_b64(*parts)
        tname = (row.get('type_name') or row.get('image_type_name') or '').strip()
        dep = int(row.get('is_deprecated') or 0)
        return {
            'image_name': image_name or '',
            'preview_b64': preview_b64,
            'image_b64': preview_b64,
            'image_asset_id': self._parse_int(row.get('image_asset_id')) or 0,
            'remark': tname,
            'image_type_name': tname,
            'description': (row.get('description') or '').strip(),
            'sort_order': self._parse_int(row.get('sort_order')) or 0,
            'is_deprecated': dep,
            'is_enabled': 0 if dep else 1,
        }

    def _read_fabric_image_items(self, conn, fabric_id):
        """读取面料已绑定图片（与图库/销售预览一致）。"""
        fid = int(fabric_id or 0)
        if not fid or not self._has_required_tables(['fabric_image_mappings', 'image_assets']):
            return []

        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_ia_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')
        join_it = "LEFT JOIN image_types it ON it.id = ia.image_type_id" if has_ia_tid else ""
        tname_sel = "it.name AS image_type_name" if has_ia_tid else "'' AS image_type_name"
        dep_expr = "COALESCE(ia.is_deprecated,0)" if has_ia_dep else "0"
        has_ia_ofn = self._table_has_column(conn, 'image_assets', 'original_filename')
        ofn_sel = "ia.original_filename AS original_filename" if has_ia_ofn else "'' AS original_filename"

        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT fim.sort_order, fim.fabric_id, ia.id AS image_asset_id,
                       ia.storage_path, {ofn_sel}, ia.description, {tname_sel}, {dep_expr} AS is_deprecated
                FROM fabric_image_mappings fim
                JOIN image_assets ia ON ia.id = fim.image_asset_id
                {join_it}
                WHERE fim.fabric_id=%s
                ORDER BY {dep_expr} ASC, fim.sort_order ASC, fim.id ASC
                """,
                (fid,),
            )
            rows = cur.fetchall() or []

        return [self._fabric_image_row_to_ui(row) for row in rows]

    def _sync_fabric_image_mappings_replace(self, conn, fabric_id, images):
        """全量替换面料图片映射（保存面料）。"""
        if not self._has_required_tables(['fabric_image_mappings', 'image_assets']):
            raise RuntimeError('缺少 fabric_image_mappings / image_assets')
        fid = int(fabric_id or 0)
        if not fid:
            return

        rows = self._image_payload_rows_for_fabric(images)
        prepared, sha_list = self._image_assets_prepared_from_rows(rows, self._resolve_fabric_image_abs_path)

        if not prepared:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM fabric_image_mappings WHERE fabric_id=%s", (fid,))
            return

        existing_by_sha = self._image_assets_upsert_batch(conn, prepared, sha_list)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_image_mappings WHERE fabric_id=%s", (fid,))
            map_rows = []
            for rec in prepared:
                aid = existing_by_sha.get(rec['sha256']) or 0
                if aid:
                    map_rows.append((fid, int(aid), int(rec.get('sort_order') or 0)))
            if map_rows:
                cur.executemany(
                    "INSERT INTO fabric_image_mappings (fabric_id, image_asset_id, sort_order) VALUES (%s,%s,%s)",
                    map_rows,
                )

    def _sync_fabric_image_mappings_append(self, conn, fabric_id, images):
        """追加面料图片映射（绑定后立即入库）。"""
        fid = int(fabric_id or 0)
        if not fid:
            return 0
        if not self._has_required_tables(['fabric_image_mappings', 'image_assets']):
            raise RuntimeError('缺少 fabric_image_mappings / image_assets')

        max_sort = -1
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(sort_order), -1) AS mx FROM fabric_image_mappings WHERE fabric_id=%s",
                (fid,),
            )
            max_sort = self._parse_int((cur.fetchone() or {}).get('mx'))
            if max_sort is None:
                max_sort = -1

        rows = self._image_payload_rows_for_fabric(images, append_after=max_sort)
        if not rows:
            return 0

        prepared, sha_list = self._image_assets_prepared_from_rows(rows, self._resolve_fabric_image_abs_path)
        if not prepared:
            return 0

        existing_by_sha = self._image_assets_upsert_batch(conn, prepared, sha_list)

        inserted = 0
        with conn.cursor() as cur:
            for rec in prepared:
                aid = existing_by_sha.get(rec['sha256']) or 0
                if not aid:
                    continue
                cur.execute(
                    "SELECT id FROM fabric_image_mappings WHERE fabric_id=%s AND image_asset_id=%s LIMIT 1",
                    (fid, int(aid)),
                )
                if cur.fetchone():
                    continue
                cur.execute(
                    "INSERT INTO fabric_image_mappings (fabric_id, image_asset_id, sort_order) VALUES (%s,%s,%s)",
                    (fid, int(aid), int(rec.get('sort_order') or 0)),
                )
                inserted += 1
        return inserted

    # -------------------------------------------------------------------------
    # 列表/表格缩略图：白底 → 场景 → 原图（其它类型不展示）
    # -------------------------------------------------------------------------

    def _table_thumb_image_type_tiers(self):
        return (
            frozenset({
                '白底纯图', '白底图', '主图·白底纯图', '主图白底纯图', '纯白底图',
                '主图·白底图', '主图白底图', '白底', 'White',
            }),
            frozenset({
                '场景图', '场景纯图', '主图·场景图', '主图场景图', '场景', 'Scene',
            }),
            frozenset({
                '原图', '平面原图', '褶皱原图',
            }),
        )

    def _table_thumb_type_priority(self, type_name):
        name = str(type_name or '').strip()
        if not name:
            return None
        for idx, tier in enumerate(self._table_thumb_image_type_tiers()):
            if name in tier:
                return idx
        return None

    def _table_thumb_row_rank_key(self, row, deprecated_key='is_deprecated', sort_key='sort_order', id_key='id'):
        return (
            self._parse_int(row.get(deprecated_key)) or 0,
            self._parse_int(row.get(sort_key)) or 0,
            self._parse_int(row.get(id_key)) or 0,
        )

    def _table_thumb_pick_best_row(self, rows, type_name_key='image_type_name', **rank_keys):
        best = None
        best_key = None
        for row in rows or []:
            priority = self._table_thumb_type_priority(row.get(type_name_key))
            if priority is None:
                continue
            rank = (priority, self._table_thumb_row_rank_key(row, **rank_keys))
            if best is None or rank < best_key:
                best = row
                best_key = rank
        return best

    def _preview_b64_from_storage_path(self, storage_path):
        sp = str(storage_path or '').strip().replace('\\', '/').lstrip('/')
        if not sp:
            return ''
        try:
            return base64.b64encode(sp.encode('utf-8', errors='surrogatepass')).decode('ascii')
        except Exception:
            try:
                return self._b64_from_fs(sp)
            except Exception:
                return ''

    def _variant_table_thumb_query_parts(self, conn):
        has_sim_tid = self._table_has_column(conn, 'sales_variant_image_mappings', 'image_type_id')
        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_ia_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')
        dep_expr = 'COALESCE(ia.is_deprecated, 0)' if has_ia_dep else '0'
        if has_sim_tid and has_ia_tid:
            type_expr = "COALESCE(NULLIF(TRIM(it_sim.name),''), NULLIF(TRIM(it_ia.name),''), '') AS image_type_name"
            join_types = """
                LEFT JOIN image_types it_ia ON it_ia.id = ia.image_type_id
                LEFT JOIN image_types it_sim ON it_sim.id = sim.image_type_id
            """
        elif has_sim_tid:
            type_expr = "COALESCE(NULLIF(TRIM(it_sim.name),''), '') AS image_type_name"
            join_types = "LEFT JOIN image_types it_sim ON it_sim.id = sim.image_type_id"
        elif has_ia_tid:
            type_expr = "COALESCE(NULLIF(TRIM(it_ia.name),''), '') AS image_type_name"
            join_types = "LEFT JOIN image_types it_ia ON it_ia.id = ia.image_type_id"
        else:
            type_expr = "'' AS image_type_name"
            join_types = ''
        return type_expr, join_types, dep_expr

    def _load_variant_table_thumb_b64(self, conn, variant_ids):
        """variant_id -> preview b64；优先级：白底 → 场景 → 原图。"""
        out = {}
        ids = [self._parse_int(x) for x in (variant_ids or []) if self._parse_int(x)]
        if not ids:
            return out
        if not self._table_has_column(conn, 'sales_variant_image_mappings', 'variant_id'):
            return out
        placeholders = ','.join(['%s'] * len(ids))
        type_expr, join_types, dep_expr = self._variant_table_thumb_query_parts(conn)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sim.variant_id,
                       ia.storage_path,
                       sim.sort_order,
                       sim.id AS sim_id,
                       {dep_expr} AS is_deprecated,
                       {type_expr}
                FROM sales_variant_image_mappings sim
                JOIN image_assets ia ON ia.id = sim.image_asset_id
                {join_types}
                WHERE sim.variant_id IN ({placeholders})
                ORDER BY sim.variant_id ASC, {dep_expr} ASC, sim.sort_order ASC, sim.id ASC
                """,
                tuple(ids),
            )
            rows = cur.fetchall() or []
        bucket = {}
        for row in rows:
            vid = self._parse_int(row.get('variant_id'))
            if not vid:
                continue
            bucket.setdefault(vid, []).append(row)
        for vid, items in bucket.items():
            picked = self._table_thumb_pick_best_row(items, id_key='sim_id')
            if not picked:
                continue
            sp = str(picked.get('storage_path') or '').strip()
            b64 = self._preview_b64_from_storage_path(sp)
            if b64:
                out[int(vid)] = b64
        return out

    def _order_product_table_thumb_query_parts(self, conn):
        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_ia_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')
        dep_expr = 'COALESCE(ia.is_deprecated, 0)' if has_ia_dep else '0'
        if has_ia_tid:
            type_expr = "COALESCE(NULLIF(TRIM(it_ia.name),''), '') AS image_type_name"
            join_types = 'LEFT JOIN image_types it_ia ON it_ia.id = ia.image_type_id'
        else:
            type_expr = "'' AS image_type_name"
            join_types = ''
        return type_expr, join_types, dep_expr

    def _load_order_product_table_thumb_b64(self, conn, order_product_ids):
        """order_product_id -> preview b64；优先级：白底 → 场景 → 原图。"""
        out = {}
        if not self._has_required_tables(['order_product_image_mappings', 'image_assets']):
            return out
        ids = [self._parse_int(x) for x in (order_product_ids or []) if self._parse_int(x)]
        if not ids:
            return out
        placeholders = ','.join(['%s'] * len(ids))
        type_expr, join_types, dep_expr = self._order_product_table_thumb_query_parts(conn)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT opim.order_product_id,
                       ia.storage_path,
                       opim.sort_order,
                       opim.id AS opim_id,
                       {dep_expr} AS is_deprecated,
                       {type_expr}
                FROM order_product_image_mappings opim
                JOIN image_assets ia ON ia.id = opim.image_asset_id
                {join_types}
                WHERE opim.order_product_id IN ({placeholders})
                ORDER BY opim.order_product_id ASC, {dep_expr} ASC, opim.sort_order ASC, opim.id ASC
                """,
                tuple(ids),
            )
            rows = cur.fetchall() or []
        bucket = {}
        for row in rows:
            opid = self._parse_int(row.get('order_product_id'))
            if not opid:
                continue
            bucket.setdefault(opid, []).append(row)
        for opid, items in bucket.items():
            picked = self._table_thumb_pick_best_row(items, id_key='opim_id')
            if not picked:
                continue
            sp = str(picked.get('storage_path') or '').strip()
            b64 = self._preview_b64_from_storage_path(sp)
            if b64:
                out[int(opid)] = b64
        return out

    def _load_order_product_table_thumb_paths(self, conn, order_product_ids):
        b64_map = self._load_order_product_table_thumb_b64(conn, order_product_ids)
        out = {}
        for opid, b64 in (b64_map or {}).items():
            if not b64:
                continue
            try:
                out[int(opid)] = base64.b64decode(b64).decode('utf-8', errors='surrogatepass')
            except Exception:
                continue
        return out

    def _attach_order_product_table_thumb_paths(self, conn, rows):
        opids = [self._parse_int(r.get('id')) for r in (rows or []) if self._parse_int(r.get('id'))]
        if not opids:
            return
        path_map = self._load_order_product_table_thumb_paths(conn, opids)
        for row in rows or []:
            opid = self._parse_int(row.get('id'))
            row['preview_image_path'] = path_map.get(opid, '') if opid else ''

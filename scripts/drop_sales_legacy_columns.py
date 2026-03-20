import argparse
import json
import os
import sys

import pymysql


LEGACY_COLUMNS = [
    'sales_intro',
    'sales_bullet_1',
    'sales_bullet_2',
    'sales_bullet_3',
    'sales_bullet_4',
    'sales_bullet_5',
    'finished_length_in',
    'finished_width_in',
    'finished_height_in',
]


def load_db_config(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_existing_columns(cur, table_name):
    cur.execute(f"SHOW COLUMNS FROM {table_name}")
    return {str(row['Field']).strip() for row in (cur.fetchall() or []) if row.get('Field')}


def build_drop_sql(table_name, columns):
    return f"ALTER TABLE {table_name} " + ", ".join([f"DROP COLUMN {col}" for col in columns])


def main():
    parser = argparse.ArgumentParser(description='安全删除 sales_products 废弃列（先预览，再执行）')
    parser.add_argument('--config', default='db_config.json', help='数据库配置文件路径（默认: db_config.json）')
    parser.add_argument('--execute', action='store_true', help='实际执行删除；不加该参数时仅预览')
    args = parser.parse_args()

    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), config_path)

    if not os.path.exists(config_path):
        print(f'[ERROR] 配置文件不存在: {config_path}')
        return 1

    db_config = load_db_config(config_path)

    conn = pymysql.connect(
        host=db_config.get('host', '127.0.0.1'),
        port=int(db_config.get('port', 3306)),
        user=db_config.get('user'),
        password=db_config.get('password'),
        database=db_config.get('database'),
        charset=db_config.get('charset', 'utf8mb4'),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )

    try:
        with conn.cursor() as cur:
            existing_cols = get_existing_columns(cur, 'sales_products')
            target_cols = [col for col in LEGACY_COLUMNS if col in existing_cols]

            print(f'[INFO] 目标表: sales_products')
            print(f'[INFO] 废弃列候选: {", ".join(LEGACY_COLUMNS)}')
            print(f'[INFO] 实际存在可删列: {", ".join(target_cols) if target_cols else "无"}')

            if not target_cols:
                print('[OK] 无需处理，退出。')
                conn.rollback()
                return 0

            sql = build_drop_sql('sales_products', target_cols)
            print('\n[SQL]')
            print(sql)

            if not args.execute:
                print('\n[DRY-RUN] 未执行删除。确认无误后加 --execute 执行。')
                conn.rollback()
                return 0

            cur.execute(sql)
            conn.commit()
            print(f'\n[OK] 已删除列: {", ".join(target_cols)}')
            return 0
    except Exception as e:
        conn.rollback()
        print(f'[ERROR] 执行失败: {e}')
        return 2
    finally:
        conn.close()


if __name__ == '__main__':
    sys.exit(main())

# SQL-only 切换清单（2026-04-01）

目标：将当前仍在运行时执行的“自动迁移（ALTER/DROP/补索引/补外键）”转为一次性 DBA SQL 脚本执行。

原则：前端只负责调用 API 做业务数据读写，不直接操作数据库结构；数据库结构变更仅通过 SQL 脚本发布。

## 1. 下单产品/基础资料（高优先级）
来源：modules/db_schema_basics_mixin.py

自动迁移点（建议转 SQL）：
- product_categories：补列 `category_en_name`
- fabric_materials：补列 `material_id`、`representative_color`；补索引/外键；删除旧列 `image_name`
- fabric_images：补列 `remark`；删除旧列 `is_primary`
- materials：补列 `name_en`、`material_type_id`、`parent_id`；补索引/唯一键/外键；`material_type_id` 改为 NOT NULL
- features：补列 `name_en`
- order_product_shipping_plans：删除旧列 `is_default`
- order_products：删除旧列 `dachene_yuncang_no/spec_qty/listing_image_b64`；补列 `is_iteration/is_dachene_product/is_on_market/contents_desc_en/factory_wip_stock/source_order_product_id`；补索引和外键
- order_product_shipping_plan_items：重建 `fk_opsi_sub_order` 删除规则为 `ON DELETE CASCADE`
- users/todos/todo_assignments/sessions：补列、删旧列、修正外键到 users、补索引
- certifications：补列 `icon_name`

## 2. 销售域
来源：modules/sales_schema_mixin.py

自动迁移点（建议转 SQL）：
- sales_parents：补业务字段与 shop 外键/索引
- sales_products：
  - 删除旧列 `portfolio_id`
  - 补列：`product_status/sku_family_id/parent_id/child_code/dachene_yuncang_no/sales_title/sale_price_usd/warehouse_cost_usd/last_mile_cost_usd/package_* /net_weight_lbs/gross_weight_lbs`
  - 删除旧列：`child_asin/parent_asin/assembled_length_in/assembled_width_in/assembled_height_in`
  - 补索引与外键：`idx_sp_sku_family/idx_sp_parent/fk_sp_sku_family/fk_sp_parent`
- sales_order_registrations：补多组性能索引；删除旧列 `is_cancelled/shipping_carrier/tracking_no`

## 3. 物流域
来源：modules/logistics_schema_mixin.py

自动迁移点（建议转 SQL）：
- logistics_overseas_warehouses：补列 `is_enabled/destination_region_id`，补索引，补外键 `fk_wh_destination_region`
- logistics_destination_regions：补列 `sort_order`，补排序索引
- logistics_in_transit：补列 `customs_clearance_no/qty_verified/qty_consistent/expected_listed_date_initial/expected_listed_date_latest/destination_region_id/confirmed_boxed_qty/remark`；字段改 nullable；补索引与外键
- logistics_in_transit_items：补列 `listed_qty`
- factory_wip_inventory：补列 `is_completed/actual_completion_date`

## 4. Amazon 广告域
来源：modules/amazon_ad_mixin.py

自动迁移点（建议转 SQL）：
- amazon_ad_operation_types：补列 `apply_portfolio/apply_campaign/apply_group`

## 5. Amazon 账户健康域
来源：modules/amazon_account_health_mixin.py

- 当前仅保留 CREATE TABLE（无 ALTER）。

## 6. 切换建议
1. 先在维护窗口执行 `scripts/sql/sql_only_migration_pack_20260401_safe.sql`
2. 执行后跑一次回归（下单产品上传、父体管理、订单登记、物流、Amazon 广告）
3. 回归通过后开启 SQL-only，彻底禁用运行时 schema ensure

## 7. SQL-only 开启与执行
变量名：`SITJOY_SQL_ONLY`

生效值：`1` / `true` / `yes` / `on`

PowerShell（当前会话）：
```powershell
$env:SITJOY_SQL_ONLY = "1"
python app.py
```

PowerShell（持久化到用户环境变量）：
```powershell
setx SITJOY_SQL_ONLY 1
```
说明：执行后需重新打开终端再启动应用。

NAS / Linux（当前会话）：
```bash
export SITJOY_SQL_ONLY=1
python3 app.py
```

说明：开启后，应用会把数据库 `_ensure_*` 方法统一降级为 no-op，运行时不再自动建表/改表/删列。

当前基线 SQL：`scripts/sql/20260401_00_schema_baseline.sql`

## 8. SQL 文件管理建议（小步脚本）
1. 每个变更点拆成独立 SQL 文件，命名建议：`YYYYMMDD_HHMM_<domain>_<action>.sql`
2. 基线文件固定为：`YYYYMMDD_00_schema_baseline.sql`
3. 每个 SQL 文件头部写明：目的、影响表、可回滚方式、执行前检查
4. 每次发布按清单顺序执行，并记录执行人、时间、环境
5. SQL 必须幂等（存在性检查 + 可重复执行）
6. 生产执行前先在预发库验证并备份

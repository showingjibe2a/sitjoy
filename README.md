# SITJOY

运行在 Synology NAS 上的内部运营 Web 应用（Python WSGI + Flask 风格路由）。覆盖产品/面料/订单、销售与销量预测、物流仓储、Amazon 广告与账户健康、图片与 A+、待办日历等模块，并提供可扩展的**小组件**（如在线围棋对弈）。

## 项目结构

```
sitjoy/
├── app.py                      # WSGI 入口：组装 Mixin、权限与菜单
├── requirements.txt
├── db_config.json              # 数据库连接（勿提交敏感信息到公开仓库）
├── AGENTS.md                   # 协作约定（含数据库 schema 策略）
├── modules/                    # 业务 Mixin（约 24 个）
│   ├── app_entry_mixin.py
│   ├── request_routing_mixin.py
│   ├── page_permission_mixin.py
│   ├── core_app_mixin.py
│   ├── auth_employee_mixin.py
│   ├── product_mgmt_mixin.py / fabric_mgmt_mixin.py / order_mgmt_mixin.py
│   ├── sales_product_mixin.py / sales_management_mixin.py
│   ├── logistics_*_mixin.py
│   ├── amazon_*_mixin.py / aplus_mixin.py
│   ├── go_play_mixin.py        # 围棋对弈 API 与房间持久化
│   └── ...
├── templates/                  # 页面模板（*.html）
├── static/
│   ├── css/                    # style.css、widgets.css 等
│   └── js/                     # 各页面前端逻辑（如 go-play.js）
├── scripts/
│   └── sql/                    # 数据库迁移（唯一允许的 schema 变更方式）
└── README.md
```

## 架构

`WSGIApp` 通过多重继承组合各 `*Mixin`，路由在 `request_routing_mixin.py` 的 `PAGE_TEMPLATE_MAP` / API 映射中集中维护，页面权限键与侧栏菜单在 `app.py` 初始化时绑定。

**原则：** 单一职责、按业务域拆分；新增功能优先新增或扩展 Mixin，避免把业务逻辑堆回 `app.py`。

## 快速开始

### 环境

- Python 3.8+
- MySQL / MariaDB
- 可 SSH 访问的 Synology NAS（或同等 Linux 环境）

### 安装与运行

```bash
cd /volume1/web/sitjoy   # 或你的部署路径

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

默认监听 `http://0.0.0.0:5000`（具体以 `app.py` / 部署配置为准）。生产环境请使用 Gunicorn/uWSGI 等 WSGI 服务器，并设置 `debug=False`。

### 依赖

| 包 | 用途 |
|----|------|
| Flask / Werkzeug | 路由与 WSGI 工具 |
| PyMySQL | 数据库 |
| openpyxl | Excel 导入导出 |
| Pillow | 图片处理 |

## 数据库迁移（重要）

**禁止**在 Python/JS 运行时自动建表、改表或探测 `information_schema`。

所有 schema 变更必须通过 `scripts/sql/*.sql` 手工执行，命名建议：`YYYYMMDD_NN_描述.sql`。基线可参考 `scripts/sql/20260423_00_schema_baseline.sql`。

详见仓库根目录 `AGENTS.md`。

## 功能模块概览

| 菜单分组 | 典型页面 | 说明 |
|----------|----------|------|
| 店铺管理 | 店铺/品牌、Amazon 账户健康 | 平台与账户监控 |
| 产品管理 | 品类货号、面料、卖点、材料、认证、下单产品 | 产品与供应链主数据 |
| 物流仓储 | 工厂/货代/海外仓、在途、工厂库存、仓储看板 | 库存与物流 |
| 图片管理 | 图库、图片类型、A+ | 素材与 listing 内容 |
| 销售管理 | 销售产品、表现看板、**销量预测**、订单登记、父体 | 销售运营 |
| Amazon 广告 | 广告信息、投放、商品、调整、关键词 | 广告域 |
| 小组件 | 围棋对弈 | 见下文 |
| 关于 | 关于页 | 站点信息 |

页面路径与权限键以 `modules/request_routing_mixin.py` 为准。

## 小组件：围棋对弈

- **入口：** `/widgets` → `/widgets/go-play`
- **前端：** `static/js/go-play.js`、`static/css/widgets.css`，模板 `templates/widgets_go_play.html`
- **独立棋盘窗口：** `/widgets/go-play/board`（`postMessage` 与主窗同步）
- **后端：** `modules/go_play_mixin.py`，API `/api/go-play`

主要能力：

- 19 路棋盘，9 星位，最后一手标记
- 房间号创建/加入，长轮询同步；未进房可本地摆棋
- 提子、打劫禁着、虚手、终局/重开
- 悔棋、认输需对方确认；对方已应手可一次撤双方各一手
- 演习模式（本地试下，结束演习恢复开局局面，不提交试下手顺）
- 棋盘可弹出独立小窗；贴边棋子完整显示（网格与落子坐标内缩对齐）

修改 `go_play_mixin.py` 后需**重启应用进程**；仅改前端/CSS/HTML 时刷新浏览器即可（必要时强刷缓存）。

## 配置

- **数据库：** `db_config.json`
- **监听地址/端口、调试开关：** `app.py` 或 WSGI 启动命令
- **页面最小宽度等全局样式：** `static/css/style.css`（如 `--sitjoy-page-min-width`）

## 生产环境建议

1. 关闭 debug，使用进程管理 + Gunicorn（示例）：
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:application
   ```
2. 前置 Nginx 反向代理与 HTTPS
3. 定期备份数据库与 `db_config.json`（勿将密钥提交到版本库）
4. 部署 SQL 迁移后再发布依赖新表结构的代码

## 故障排除

| 现象 | 处理 |
|------|------|
| 端口占用 | 修改端口或结束占用进程 |
| 模块未找到 | `pip install -r requirements.txt` |
| 页面 500 / 字段缺失 | 确认是否已执行对应 `scripts/sql` 迁移 |
| 围棋状态不同步 | 确认多 worker 共享同一房间数据目录；重启服务 |

## 开发说明

- 新页面：在 `request_routing_mixin.py` 注册路由与 API，在 `app.py` 的 `label_map` / `PAGE_PERMISSION_GROUPS` 中加入权限与菜单项
- 静态资源：业务 CSS 可放 `static/css/`，小组件样式放 `widgets.css`
- 协作约束：阅读并遵守 `AGENTS.md`

## 许可证

MIT License

---

**最后更新：** 2026-05-22

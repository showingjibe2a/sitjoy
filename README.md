# Synology NAS Python 网页项目

这是一个运行在 Synology NAS 上的 Python Flask Web 应用。

## 📋 项目结构

```
sitjoy/
├── app.py                      # WSGI 应用入口（5,351行）- 负责mixin组装和基础路由
├── requirements.txt            # Python 依赖
├── README.md                   # 说明文档
├── db_config.json             # 数据库配置
├── templates/                 # HTML 模板文件夹
│   └── *.html                 # 各功能模块的页面模板
├── static/                    # 静态资源文件夹
│   ├── css/
│   │   └── style.css         # 样式表
│   ├── js/
│   └── partials/
├── modules/                   # 业务逻辑 Mixin 模块（23个）
│   ├── app_entry_mixin.py         # WSGI 入口处理
│   ├── auth_employee_mixin.py      # 员工认证和会话管理
│   ├── core_app_mixin.py          # 核心基础设施（DB连接、JSON响应、缓存）
│   ├── db_schema_basics_mixin.py   # 数据库 schema 初始化
│   ├── page_permission_mixin.py    # 页面权限管理
│   ├── request_routing_mixin.py    # API 请求路由分发
│   ├── excel_tools_mixin.py        # Excel 导入导出处理
│   ├── encoding_utils_mixin.py     # 编码和文本规范化工具
│   ├── image_processing_mixin.py   # 图片识别和处理
│   ├── file_utils_mixin.py         # 文件系统操作工具
│   ├── file_management_mixin.py    # 文件管理和上传
│   ├── product_mgmt_mixin.py       # SKU/分类/材料管理（新增）
│   ├── fabric_mgmt_mixin.py        # 面料管理和图片处理（新增）
│   ├── order_mgmt_mixin.py         # 订单产品管理（新增）
│   ├── utility_mixin.py            # 待办/日历/卖点工具（新增）
│   ├── amazon_ad_mixin.py          # Amazon 广告管理（新增）
│   ├── support_domain_mixin.py     # 平台/品牌/店铺/认证管理（新增）
│   ├── sales_product_mixin.py      # 销售产品管理
│   ├── sales_management_mixin.py   # 订单登记管理
│   ├── sales_schema_mixin.py       # 销售模块 schema
│   ├── logistics_warehouse_mixin.py    # 海外仓库管理
│   ├── logistics_in_transit_mixin.py   # 在途物流管理
│   ├── logistics_schema_mixin.py       # 物流 schema
│   ├── amazon_account_health_mixin.py  # Amazon 账户健康监控
│   └── __pycache__/            # Python 编译缓存
├── scripts/                   # 辅助脚本
│   ├── list_fabric_files.py
│   ├── diagnose_fabric_binding.py
│   └── patch_*.py
└── __pycache__/              # 缓存目录
    ├── logistics_schema_ready.json
    ├── opt_cache_*.json      # API 选项缓存
    └── user_perm_*.json      # 用户权限缓存
```

## 🏗️ 架构设计

### Mixin 继承结构

WSGIApp 通过多重继承组装 23 个 Mixin 模块，实现关注点分离：

```
WSGIApp
├── AppEntryMixin              # WSGI 入口
├── RequestRoutingMixin        # 路由分发
├── PagePermissionMixin        # 权限检查
├── CoreAppMixin               # 核心基础
├── AuthEmployeeMixin          # 认证管理
├── UtilityMixin              # 工具函数
├── [编码/图片/文件处理]      # 基础设施
├── DbSchemaBasicsMixin        # 数据库初始化
├── [Schema定义Mixin]         # 各模块 Schema
├── [域驱动业务Mixin]         # 11 个业务模块
```

**优势**:
- ✅ 单一职责：每个 Mixin 专注于特定功能
- ✅ 高度内聚：相关代码聚合在一起
- ✅ 低耦合：模块之间依赖清晰
- ✅ 易测试：单个 Mixin 可独立验证
- ✅ 易扩展：新功能只需添加新 Mixin

### 重构历程  

| 阶段 | app.py 行数 | 新增 Mixin | 主要工作 |
|------|-----------|----------|--------|
| 初始 | 11,002 | 14 | 单体架构 |
| 第一阶段 | 8,500 | +6 | 域驱动拆分 |
| 第二阶段 | 6,200 | +3 | 功能细分 |
| **最终** | **5,351** | **23** | **-51.4%** |

## 🚀 快速开始

### 前置要求
- Synology NAS 已安装 Python 3.8 或更高版本
- SSH 访问 NAS
- MySQL/MariaDB 数据库

### 安装步骤

1. **连接到 NAS**
   ```bash
   ssh admin@your-nas-ip
   ```

2. **进入项目目录**
   ```bash
   cd /volume1/web/sitjoy
   ```

3. **创建虚拟环境（推荐）**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/NAS
   ```

4. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

5. **运行应用**
   ```bash
   python app.py
   ```

应用将在 `http://localhost:5000` 启动

## 🌐 访问网页

从任何设备访问：
- **本地 NAS：** `http://nas-ip:5000`
- **本地机器：** `http://localhost:5000`（需要端口转发）

## 📡 API 端点

| 方法 | 路由 | 说明 |
|------|------|------|
| GET | `/` | 首页 |
| GET | `/about` | 关于页面 |
| POST | `/api/hello` | 问候 API（POST JSON：`{"name": "用户名"}`) |
| GET | `/api/hello?name=用户名` | 问候 API（GET 方式） |
| GET | `/status` | 系统状态信息 |

## 📝 示例 API 调用

### 测试问候 API
```bash
curl -X POST http://localhost:5000/api/hello \
  -H "Content-Type: application/json" \
  -d '{"name": "张三"}'
```

响应：
```json
{
  "message": "你好，张三！",
  "timestamp": "2026-01-20T10:30:00.123456",
  "status": "success"
}
```

### 获取系统状态
```bash
curl http://localhost:5000/status
```

## 🔧 配置说明

在 `app.py` 中修改以下内容：

```python
app.run(
    host='0.0.0.0',    # 0.0.0.0 允许外部访问，localhost 仅本地
    port=5000,         # 修改端口号
    debug=True         # 生产环境改为 False
)
```

## 📦 依赖列表

- Flask 2.3.3 - Web 框架
- Werkzeug 2.3.7 - WSGI 工具库

## 🛡️ 生产环境建议

1. 设置 `debug=False`
2. 使用 Gunicorn 作为 WSGI 服务器：
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. 在 Nginx 后面运行作为反向代理

4. 设置 SSL/TLS 证书加密

## 🐛 故障排除

### 端口被占用
```bash
# 更改 app.py 中的 port 参数
# 或杀死占用端口的进程
lsof -i :5000  # 查找进程
kill -9 <PID>  # 杀死进程
```

### 权限问题
```bash
chmod +x app.py
```

### 模块未找到
```bash
pip install -r requirements.txt --upgrade
```

## 🧹 清理临时文件

在大规模重构过程中生成了以下临时文件，这些文件已不再需要，可以安全删除：

### 需要删除的文件

```
extract_to_mixin.py                      # AST 方法提取脚本
create_remaining_mixins_template.py      # Mixin 批量生成模板
ADVANCED_SUBDIVISION_REPORT.md           # 详细重构分析报告（5+ 页）
REFACTORING_REPORT.md                    # 重构摘要与统计
final_cleanup.py                         # 旧的清理脚本
cleanup_app.py                           # 旧的清理脚本
extract_amazon.py                        # 旧的 Amazon 提取脚本
```

### 删除方法

**使用 PowerShell（Windows）：**
```powershell
cd \\diskstation\web\sitjoy
Remove-Item extract_to_mixin.py -Force
Remove-Item create_remaining_mixins_template.py -Force
Remove-Item ADVANCED_SUBDIVISION_REPORT.md -Force
Remove-Item REFACTORING_REPORT.md -Force
Remove-Item final_cleanup.py -Force
Remove-Item cleanup_app.py -Force
Remove-Item extract_amazon.py -Force
```

**使用 SSH（NAS）：**
```bash
cd /volume1/web/sitjoy
rm -f extract_to_mixin.py
rm -f create_remaining_mixins_template.py
rm -f ADVANCED_SUBDIVISION_REPORT.md
rm -f REFACTORING_REPORT.md
rm -f final_cleanup.py
rm -f cleanup_app.py
rm -f extract_amazon.py
```

### 清理说明

这些文件是 Mixin 重构过程（初始→第一阶段→第二阶段）中生成的临时产物：

- **extract_* 脚本**：用于从 app.py 中自动提取方法到新 Mixin 模块
- **REPORT 文件**：记录重构过程中的设计决策和变更历史
- **cleanup_* 脚本**：之前版本的清理工具，已由新的 Mixin 架构取代

删除这些文件不会影响应用功能，只会减少项目文件夹大小。

## 🔄 最近大规模重构

### 重构背景

为了解决单体应用代码量过大的问题，将原始的 11,002 行 app.py 拆分为 23 个专注于特定功能域的 Mixin 模块。

### 重构成果

- ✅ **代码规模减少 51.4%**：11,002 行 → 5,351 行（app.py）
- ✅ **模块数增加 64%**：14 个 → 23 个 Mixin
- ✅ **代码可读性提升**：平均 250 行/模块，便于快速定位问题
- ✅ **维护成本降低**：高内聚低耦合的双重目标

### 新增核心 Mixin（6 个）

| Mixin | 职责 | 页面 |
|------|------|------|
| `ProductMgtMixin` | SKU/分类/材料/卖点 | product_management, sales_product |
| `FabricMgtMixin` | 面料库和图片关联 | fabric_management |
| `OrderMgtMixin` | 订单产品与关联 | order_product_management |
| `UtilityMixin` | 待办/日历/工具函数 | 跨模块 |
| `AmazonAdMixin` | Amazon 广告管理 | amazon_ad_* |
| `SupportDomainMixin` | 平台/品牌/店铺/认证 | shop/platform 相关 |

## 📚 进一步学习

- [Flask 官方文档](https://flask.palletsprojects.com/)
- [Python 官方文档](https://docs.python.org/)
- [Synology 开发者指南](https://developer.synology.com/)
- [Mixin 模式最佳实践](https://en.wikipedia.org/wiki/Mixin)

## 📄 许可证

MIT License

## 👤 作者

你的 Synology NAS

---

**最后更新：** 2026-01-20  
**重构版本：** 第二阶段（2026-01 完成）  
**稳定性：** 已修复所有关键生产缺陷

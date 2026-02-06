# Synology NAS Python 网页项目

这是一个运行在 Synology NAS 上的 Python Flask Web 应用。

## 📋 项目结构

```
sitjoy/
├── app.py                 # Flask 主应用
├── requirements.txt       # Python 依赖
├── README.md             # 说明文档
├── templates/            # HTML 模板文件夹
│   ├── index.html       # 首页
│   └── about.html       # 关于页面
└── static/              # 静态资源文件夹
    └── css/
        └── style.css    # 样式表
```

## 🚀 快速开始

### 前置要求
- Synology NAS 已安装 Python 3.8 或更高版本
- SSH 访问 NAS

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
   # 或
   venv\Scripts\activate    # Windows
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

## 📚 进一步学习

- [Flask 官方文档](https://flask.palletsprojects.com/)
- [Python 官方文档](https://docs.python.org/)
- [Synology 开发者指南](https://developer.synology.com/)

## 📄 许可证

MIT License

## 👤 作者

你的 Synology NAS

---

**最后更新：** 2026-01-20

# SITJOY 样式与组件定制规范

## 目标

提供**可扩展接口**，便于日后为每个小组件单独设计变体（如 `status-segment`、`app-date-input`），而不是内置多套成品主题皮肤。

## 文件职责

| 文件 | 职责 |
|------|------|
| `tokens.css` | 全局与组件默认令牌 `--sj-*`、`--sj-cmp-*` |
| `theme-engine.css` | `html[data-sj-*="变体"]` 对令牌的覆盖 + 首页样式面板 |
| `style.css` | 布局与组件结构；颜色/质感优先 `var(--sj-…)` |
| `theme.js` | 组件注册表、持久化、`mountPanel` |

## 三层模型

```
tokens.css（默认值）
    ↓ 被覆盖
html[data-sj-statusSegment="compact"] { --sj-cmp-status-segment-radius: 10px; }
    ↓ 被使用
.status-segment { border-radius: var(--sj-cmp-status-segment-radius, 999px); }
```

1. **令牌**：`--sj-variant-*`（顶栏、卡片、弹窗等整组件）  
2. **子组件令牌**：`--sj-cmp-{组件}-*`（status-segment、date-input 等）  
3. **变体开关**：`html` 上的 `data-sj-{dataAttr}="{variant}"`（由 `theme.js` 写入）

## 新增一个可定制组件（四步）

### 1. `theme.js` → `COMPONENT_REGISTRY`

```javascript
SitjoyTheme.registerComponent({
  id: 'myWidget',
  dataAttr: 'sjMyWidget',  // → html[data-sj-my-widget]
  label: '我的组件',
  variants: { default: '默认', bold: '强调' }
});
```

### 2. `tokens.css` 增加默认令牌

```css
--sj-cmp-my-widget-border: 1px solid var(--morandi-sand);
```

### 3. `theme-engine.css` 写变体覆盖

```css
html[data-sj-my-widget="bold"] {
  --sj-cmp-my-widget-border: 2px solid var(--morandi-ink);
}
```

### 4. 业务 CSS 使用变量

```css
.my-widget {
  border: var(--sj-cmp-my-widget-border);
}
```

## 未来整站主题（可选）

新建 `themes/your-name.css`：

```css
html[data-theme="your-name"] {
  --sj-bg-body: linear-gradient(...);
  --sj-variant-card-bg: ...;
}
```

在 `style.css` 顶部 `@import url('themes/your-name.css');`  
**不要**在 `theme.js` 里硬编码多套成品主题；主题 id 仅作 `html[data-theme]` 钩子。

## 用户界面

- 首页个人信息区最右侧：**「桌面美化」** 文件夹分组，内含图标+文字的快捷入口（如「组件样式」）。
- 点击「组件样式」打开 **弹窗** 配置各组件变体。
- 「编辑资料」「登出」在姓名右侧；登出使用 `btn-danger btn-small`。
- 仅当某组件 `variants` 多于 `default` 时，弹窗内下拉框可切换。

## JS API

```javascript
SitjoyTheme.setComponentVariant('statusSegment', 'compact');
SitjoyTheme.loadPrefs();
SitjoyTheme.mountHomeLauncher();
SitjoyTheme.openModal();
SitjoyTheme.closeModal();
document.addEventListener('sitjoy:theme-change', (e) => console.log(e.detail));
```

## 已注册组件（示例）

| id | data 属性 | 说明 |
|----|-----------|------|
| statusSegment | `data-sj-status-segment` | `.status-segment` / `--inline` |
| dateInput | `data-sj-date-input` | `.app-date-input` 等 |
| navbar, card, modal, profile, button, table, formInput | 同上 | 预留，变体可在 CSS 中自行添加 |

## 约定

- 页面背景保持 `--sj-bg-body` 深色渐变；卡片/弹窗为浅色表面，勿把整个页面改亮。
- 新样式避免写死 `#hex`；沿用 `--morandi-*` 或 `--sj-*`。
- 禁止运行时改数据库表结构（见 `AGENTS.md`）。

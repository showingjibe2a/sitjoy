# SITJOY 样式与组件定制规范

## 目标

提供**可扩展接口**，便于日后为每个小组件单独设计变体（如 `status-segment`、`app-date-input`），而不是内置多套成品主题皮肤。

## 文件职责

| 文件 | 职责 |
|------|------|
| `tokens.css` | 全局与组件默认令牌 `--sj-*`、`--sj-cmp-*` |
| `theme-engine.css` | `html[data-sj-*="变体"]` 对令牌的覆盖 + 小组件样式配置页 |
| `style.css` | 布局与组件结构；颜色/质感优先 `var(--sj-…)` |
| `theme.js` | 组件注册表、持久化、`mountStudioPage` |

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

- **小组件 → 组件样式**（`/widgets/theme`）：全站 UI 按组件分区管理；先调「基础色板」，再微调各组件颜色；设置保存在本浏览器，全站即时生效。
- **应用壳**（`app-shell.css`）：仅布局；颜色一律走 `tokens.css` 中的 `--sj-variant-*`。
- 「关于」位于侧栏 **系统管理** 分组下。

## 已注册组件（组件样式页）

| id | 说明 |
|----|------|
| palette | 莫兰迪基础色（`--morandi-*`），联动全站 |
| pageBody | 页面深色底纹与渐变顶色 |
| navbar / sidebar / tabs | 应用壳顶栏、侧栏、页签 |
| iconCircle | 关闭(×)、帮助(?)、通知、固定等圆形微按钮 |
| hero | 深色底上的页标题 |
| card / modal / button / table / formInput | 业务卡片、弹窗、按钮、表格、输入 |
| notification / toast | 通知面板与右下角提示条 |
| statusSegment / dateInput | 状态分段、日期输入（含 compact 变体） |

## JS API

```javascript
SitjoyTheme.setComponentVariant('statusSegment', 'compact');
SitjoyTheme.setCustomColor('--morandi-cream', '#ece7df');
SitjoyTheme.loadPrefs();
SitjoyTheme.mountStudioPage('sitjoyThemeStudio');
SitjoyTheme.resetAllPrefs();
document.addEventListener('sitjoy:theme-change', (e) => console.log(e.detail));
```

仅当某组件 `variants` 多于 `default` 时，变体下拉框可切换。

## 约定

- 页面背景保持 `--sj-bg-body` 深色渐变；卡片/弹窗为浅色表面，勿把整个页面改亮。
- 新样式避免写死 `#hex`；沿用 `--morandi-*` 或 `--sj-*`。
- 禁止运行时改数据库表结构（见 `AGENTS.md`）。

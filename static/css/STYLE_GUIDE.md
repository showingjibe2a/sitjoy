# SITJOY 样式与组件定制规范

## 目标

- **一套可读的 `sj-*` 类名**：见名知意，新页面直接复用。
- **一个 JS 入口 `SitjoyPageUI`**：下拉、托管表、状态分段、筛选条统一初始化。
- **主题可扩展**：组件变体走 `theme.js` + `tokens.css`（见下文三层模型）。

## 文件职责

| 文件 | 职责 |
|------|------|
| `tokens.css` | 全局与组件默认令牌 `--sj-*`、`--sj-cmp-*` |
| `theme-engine.css` | `html[data-sj-*="变体"]` 覆盖 + 组件样式配置页 |
| `sitjoy-ui-patterns.css` | **全站 UI 模式**（`sj-option-bar`、`sj-chip-picker-create` 等） |
| `style.css` | 布局、表格、弹窗、表单；颜色走 `var(--sj-…)` |
| `sitjoy_page_ui.js` | `SitjoyPageUI` API（由 `header.js` 自动加载） |
| `header.js` | 顶栏、托管表 `SitjoyManagedPmTable`、Universal 下拉、Toast/钉钉 |
| `theme.js` | 组件注册表、持久化、`mountStudioPage` |

## 新页面 checklist

1. 引入 `style.css`（已含 `sitjoy-ui-patterns.css`）。
2. 页末 `<script src="/static/js/header.js"></script>`（自动加载 `sitjoy_page_ui.js`）。
3. 在 `load` 或 `sitjoy:page-ui-ready` 后调用：

```javascript
SitjoyPageUI.init({
    selects: true,                    // 增强所有原生 <select>
    tables: '#myTable',               // 或 true = 全部 .pm-table
    statusSegments: true,             // 绑定 .status-segment[data-sj-status-segment]
    modals: [{ el: '#my-modal', onClose: closeModal }],
    onReady() { /* 本页数据加载 */ },
});
```

4. **勿**在 `<style>` 里复制 `required-field`、`status-pill`、`upload-progress` 等全局规则。
5. 上传进度用 `showAppUploadProgress()`，勿新建 `.upload-progress` 块。

---

## 首选类名速查（`sj-*`）

| 类名 | 用途 | 旧名（仍兼容） |
|------|------|----------------|
| `sj-option-bar` | 横向筛选/标签条容器 | `material-type-bar`, `option-bar`, `image-type-bar` |
| `sj-option-add` | 条上绿色「+」 | `material-type-add`, `option-add` |
| `sj-option-radio` | 条内单选 chip（`label` + 隐藏 `input`） | `material-type-radio`, `option-radio` |
| `sj-option-pill` | 条内纯按钮 pill（双击编辑等） | `material-type-pill` |
| `status-segment` + `status-pill` | 是/否、启用/停用分段 | — |
| `status-segment--inline` | 表单内紧凑分段 | — |
| `status-pill--yes` / `--no` 等 | 激活色语义 | 见 `style.css` |
| `pm-table` | 数据表外观 + 托管表基础 | 可加 `sj-table` 作标记 |
| `inline-input` | 表内/行内小输入框 | — |
| `required-field` / `optional-field` | 必填/选填底纹 | 全局，勿内联覆盖 |
| `universal-select-trigger` 等 | 增强下拉（由 JS 生成） | 勿用 `pm-select`（旧） |
| `feature-category-picker` | 多选 chip 面板 | 单选下拉用 universal-select |
| `sj-chip-picker-create` | chip 面板内「新增」绿钮 | `feature-category-create` |
| `sj-form-grid-full` | 表单 grid 跨列 | `pm-form-full` |
| `sj-text-negative` | 负面文案色 | `sku-market-off` |
| `pm-modal` | 业务弹窗 | 勿用首页遗留 `.modal` |

---

## SitjoyPageUI API

```javascript
// 筛选/标签条（替代各页手写 renderXxxBar）
SitjoyPageUI.renderOptionBar('#filterBar', {
    mode: 'radio',           // 'radio' | 'pill'
    radioName: 'typeFilter',
    selectedValue: '',
    items: [{ id: 1, label: '餐椅', raw: row }],
    onSelect(value, item) { /* 筛选列表 */ },
    onItemDblClick(item) { /* 打开编辑 */ },
    onItemMount(label, item, mode) { /* 如区域条拖拽排序 */ },
    showAdd: true,
    onAdd() { /* 新增 */ },
});

// 状态分段（是/否、在市/下市）
SitjoyPageUI.bindStatusSegment('#mySegment', { onChange(val) {} });
SitjoyPageUI.getStatusSegmentValue('#mySegment');
SitjoyPageUI.setStatusSegmentValue('#mySegment', '1');

// 表格（包装 SitjoyManagedPmTable）
SitjoyPageUI.enhanceTables('#skuTable');
// 纯展示、不要排序筛选时： <table data-disable-table-manage="1">

// 下拉
SitjoyPageUI.enhanceSelects(document);
```

HTML 状态分段示例：

```html
<!-- data-sj-status-segment 仅标在 .status-segment 上；勿与主题变体混用（html 上用 data-sj-status-segment-variant） -->
<div class="status-segment status-segment--inline" id="seg" data-sj-status-segment data-value="1">
    <button type="button" class="status-pill status-pill--yes is-active" data-value="1">是</button>
    <button type="button" class="status-pill status-pill--no" data-value="0">否</button>
</div>
```

---

## 表格：两层能力

| 层级 | 用法 |
|------|------|
| **样式** | `<table class="pm-table">` — 全站表格外观 |
| **行为** | `SitjoyPageUI.enhanceTables()` → 排序、列筛选、分页、格选、批量条（`header.js`） |

复杂页（在途、销量预测、产品表现）可在 `tableOptions` / `registerServerList` 等传页面特有配置；**结构仍用 `pm-table`**。

表内编辑：`.inline-input`；表内状态：`.status-segment`（托管表已识别）。

列筛选按钮类名：**`pm-column-filter-btn`**（勿用已废弃的 `wip-col-filter-btn`）。

---

## 下拉：只用 Universal Select

- 原生 `<select>` + `initUniversalSingleSelects`（`SitjoyPageUI.init({ selects: true })`）。
- 多选 chip：`feature-category-picker` 结构（面料、卖点等）。
- **迁移中**：`pm-select` 仅保留在少数旧页，新页禁止新增。

---

## 三层主题模型

```
tokens.css（默认值）
    ↓ 被覆盖
html[data-sj-statusSegment="compact"] { … }
    ↓ 被使用
.status-segment { border-radius: var(--sj-cmp-status-segment-radius); }
```

新增可定制组件：见下文「新增组件四步」。

---

## 新增一个可定制组件（四步）

### 1. `theme.js` → `COMPONENT_REGISTRY`

### 2. `tokens.css` 增加 `--sj-cmp-*` 默认令牌

### 3. `theme-engine.css` 写变体覆盖

### 4. 业务 CSS 使用 `var(--sj-cmp-*)`

---

## 已注册组件（组件样式页）

| id | 说明 |
|----|------|
| palette | 莫兰迪基础色 |
| pageBody / navbar / sidebar / tabs | 应用壳 |
| card / modal / button / table / formInput | 业务表面 |
| statusSegment / dateInput | 状态分段、日期 |
| dingtalkNotifyPrompt | 钉钉确认条 |

```javascript
SitjoyTheme.setComponentVariant('statusSegment', 'compact');
document.addEventListener('sitjoy:theme-change', (e) => console.log(e.detail));
```

---

## 约定

- 页面背景 `--sj-bg-body`；卡片/弹窗浅色表面。
- 新样式避免写死 `#hex`；用 `--morandi-*` / `--sj-*`。
- 禁止运行时改数据库表结构（见 `AGENTS.md`）。

---

## 迁移进度（样式统一）

| 状态 | 内容 |
|------|------|
| 已完成 | `sitjoy-ui-patterns.css`（含 `pm-select`/`sj-upload-progress`/`sj-dialog-message` 全局规则） |
| 已完成 | `SitjoyPageUI`：`renderOptionBar`、`onItemMount`、货号/材料/店铺品牌/首页待办/海外仓供应商·区域/在途货代筛选条 |
| 已完成 | 去除各页内联 `required-field`、`upload-progress`、`status-pill` 焦点、`preview-savebar` 重复 |
| 已完成 | 废弃 `wip-col-filter-btn`（仅保留 `pm-column-filter-btn`） |
| 已完成 | `SitjoyPageUI.init`：货号、材料、店铺品牌、海外仓仓库 |
| 遗留 | `image-type-bar` 主图类型条（销售/下单/面料等大页内嵌逻辑，类名已别名到 `sj-option-bar`） |
| 遗留 | `pm-select` DOM 结构 → universal-select（大页渐进迁移，样式已由全局覆盖） |
| 遗留 | `sales_product_performance` 的 `check-select` 与 universal 对齐（待评估） |

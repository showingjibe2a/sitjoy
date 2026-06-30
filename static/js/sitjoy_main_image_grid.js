/**
 * 主图网格控制器：卡片渲染、启用/弃用样式与排序、拖拽重排、状态切换。
 * 各页仅注入 API/实体差异（adapter），UI 与交互逻辑在此统一维护。
 */
(function (global) {
  const Card = () => global.SjMediaImageCard;

  // -------------------------------------------------------------------------
  // 主图网格控制器
  // -------------------------------------------------------------------------
  function escapeAttr(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function MainImageGrid(options) {
    this.opts = options && typeof options === 'object' ? options : {};
    this._dragIdx = null;
    this._dragInsert = null;
  }

  MainImageGrid.prototype.getGridEl = function () {
    if (this.opts.gridEl) return this.opts.gridEl;
    if (this.opts.gridId) return document.getElementById(this.opts.gridId);
    return null;
  };

  MainImageGrid.prototype.getTipEl = function () {
    if (this.opts.tipEl) return this.opts.tipEl;
    if (this.opts.tipId) return document.getElementById(this.opts.tipId);
    return null;
  };

  MainImageGrid.prototype.getFilterType = function () {
    const v = this.opts.getFilterType ? this.opts.getFilterType() : '全部';
    return String(v || '全部').trim() || '全部';
  };

  MainImageGrid.prototype.itemKey = function (item) {
    if (typeof this.opts.itemKey === 'function') return this.opts.itemKey(item);
    return String(item && item.image_name || '').trim();
  };

  MainImageGrid.prototype.previewUrl = function (item) {
    if (typeof this.opts.previewUrl === 'function') return this.opts.previewUrl(item);
    const b64 = String(item && item.image_b64 || '').trim();
    if (!b64) return '';
    return `/api/image-preview?id=${encodeURIComponent(b64)}&mode=thumb&w=540&q=72`;
  };

  MainImageGrid.prototype.getFabricCandidatesOpts = function () {
    const fn = this.opts.fabricCandidates;
    if (typeof fn !== 'function') return {};
    return { fabricCandidates: fn() };
  };

  MainImageGrid.prototype.getViewList = function () {
    if (typeof this.opts.getViewList === 'function') {
      return this.opts.getViewList();
    }
    const filterType = this.getFilterType();
    const items = (this.opts.getItems ? this.opts.getItems() : []) || [];
    const filtered = items.slice().filter((x) =>
      filterType === '全部' || String(x.image_type_name || '').trim() === filterType
    );
    const C = Card();
    if (C && typeof C.sortItemsByEnabled === 'function') {
      return C.sortItemsByEnabled(filtered, C.defaultImageListCompare);
    }
    return filtered;
  };

  MainImageGrid.prototype._resolveCardClassName = function (item) {
    let base;
    if (typeof this.opts.cardClassName === 'function') {
      base = this.opts.cardClassName(item);
    } else {
      const C = Card();
      base = (C && C.buildCardClassName) ? C.buildCardClassName(item) : 'sj-media-image-card sj-media-image-card--drag';
    }
    const extra = typeof this.opts.cardClassExtra === 'function' ? this.opts.cardClassExtra(item) : '';
    return [base, extra].filter(Boolean).join(' ').trim();
  };

  MainImageGrid.prototype._resolveInfoItem = function (item) {
    if (typeof this.opts.mapInfoItem === 'function') return this.opts.mapInfoItem(item);
    return item;
  };

  MainImageGrid.prototype._buildMergedRenderList = function () {
    const filterType = this.getFilterType();
    const list = this.getViewList();
    const overlay = this.opts.fabricOverlay;
    const showFabric = overlay && (typeof overlay.isVisible !== 'function' || overlay.isVisible());
    const fabricItems = overlay && typeof overlay.getItems === 'function' ? overlay.getItems() : [];
    const hasFabric = !!(showFabric && fabricItems && fabricItems.length);
    let merged = list.slice();
    if (hasFabric) {
      const fabricMarked = fabricItems.slice()
        .filter((x) => filterType === '全部' || String(x.image_type_name || '').trim() === filterType)
        .map((it) => Object.assign({}, it, { is_fabric_image: true }));
      merged = merged.concat(fabricMarked);
    }
    const C = Card();
    const compareFn = (C && typeof C.defaultImageListCompareWithFabricAfterMain === 'function')
      ? C.defaultImageListCompareWithFabricAfterMain
      : ((C && C.defaultImageListCompare) || null);
    if (C && typeof C.sortItemsByEnabled === 'function') {
      return C.sortItemsByEnabled(merged, compareFn);
    }
    if (compareFn) merged.sort(compareFn);
    return merged;
  };

  MainImageGrid.prototype.render = function () {
    const grid = this.getGridEl();
    if (!grid) return;
    const tip = this.getTipEl();
    const msgs = this.opts.messages || {};
    const entityId = this.opts.getEntityId ? this.opts.getEntityId() : null;
    const self = this;

    if (entityId === null || entityId === undefined || entityId === '' || entityId === 0) {
      if (this.opts.skipEntityCheck) {
        /* 面料等本地编辑：无远程实体 ID 仍渲染 */
      } else {
        if (tip && msgs.noEntityTip) tip.textContent = msgs.noEntityTip;
        grid.innerHTML = `<div class="sj-media-image-empty">${escapeAttr(msgs.noEntityEmpty || '请先保存后再管理主图')}</div>`;
        return;
      }
    }

    const overlay = this.opts.fabricOverlay;
    const showFabric = overlay && (typeof overlay.isVisible !== 'function' || overlay.isVisible());
    const fabricItems = overlay && typeof overlay.getItems === 'function' ? overlay.getItems() : [];
    const hasFabric = !!(showFabric && fabricItems && fabricItems.length);
    const allItems = (this.opts.getItems ? this.opts.getItems() : []) || [];
    const totalCount = typeof this.opts.getTotalCount === 'function'
      ? this.opts.getTotalCount()
      : allItems.length;

    if (!totalCount && !hasFabric) {
      grid.innerHTML = `<div class="sj-media-image-empty">${escapeAttr(msgs.empty || '暂无图片')}</div>`;
      return;
    }

    const list = this._buildMergedRenderList();
    if (!list.length) {
      grid.innerHTML = `<div class="sj-media-image-empty">${escapeAttr(msgs.filteredEmpty || msgs.empty || '当前筛选下暂无图片')}</div>`;
      return;
    }
    const fcOpts = this.getFabricCandidatesOpts();
    const C = Card();
    const drag = this.opts.dragReorder === true || this.opts.dragReorder === 1;

    grid.innerHTML = '';
    const placeholder = document.createElement('div');
    placeholder.className = 'sj-media-image-card placeholder';
    placeholder.style.display = 'none';
    if (drag) {
      placeholder.style.minHeight = '80px';
      placeholder.style.borderStyle = 'dashed';
      placeholder.style.opacity = '0.6';
    }

    let mainIndex = 0;
    list.forEach((item) => {
      if (item && item.is_fabric_image) {
        grid.appendChild(this._createFabricCard(item, fcOpts));
      } else {
        grid.appendChild(this._createMainCard(item, mainIndex, fcOpts, drag));
        mainIndex += 1;
      }
    });

    grid.appendChild(placeholder);
    if (this.opts.statusSegments !== false) {
      this._bindStatusSegments(grid);
    }
    if (drag) this._bindDrag(grid, placeholder);
  };

  // -------------------------------------------------------------------------
  // 卡片创建、启用态与拖拽重排
  // -------------------------------------------------------------------------
  MainImageGrid.prototype._createMainCard = function (item, index, fcOpts, drag) {
    const self = this;
    const C = Card();
    const rawName = String(item.image_name || '');
    const rowKey = this.itemKey(item);
    const safeName = escapeAttr(rawName);
    const card = document.createElement('div');
    card.className = this._resolveCardClassName(item);
    if (drag) {
      card.style.cursor = 'move';
      card.setAttribute('draggable', 'true');
    }
    card.dataset.imageName = rawName;
    card.dataset.rowKey = rowKey;
    card.dataset.index = String(index);

    const preview = this.previewUrl(item);
    const previewHtml = preview
      ? `<img src="${escapeAttr(preview)}" alt="${safeName}" class="sj-media-image-preview" loading="lazy">`
      : '<div style="width:100%;height:100%;border:1px dashed var(--morandi-sand);border-radius:12px;background:rgba(0,0,0,0.02);"></div>';

    const infoItem = this._resolveInfoItem(item);
    const infoOpts = Object.assign({}, fcOpts, { readonly: this.opts.infoReadonly === true });
    const infoHtml = (C && C.buildInfoHtml) ? C.buildInfoHtml(infoItem, infoOpts) : '';

    const deleteHtml = this.opts.hideDeleteBadge
      ? ''
      : '<div class="sj-media-image-remove-badge"><span class="sj-media-image-remove-icon">×</span></div>';

    card.innerHTML = `
      ${deleteHtml}
      <div class="sj-media-image-preview-wrap">${previewHtml}</div>
      ${infoHtml}`;

    card.querySelector('.sj-media-image-remove-badge')?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (typeof self.opts.onDelete === 'function') self.opts.onDelete(item, rowKey);
    });

    if (typeof this.opts.onEdit === 'function') {
      card.addEventListener('dblclick', () => self.opts.onEdit(item, rowKey));
    }

    if (drag) {
      const bindDrag = (el) => {
        el.addEventListener('dragstart', (e) => self._onDragStart(e));
        el.addEventListener('dragenter', (e) => self._onDragEnter(e));
        el.addEventListener('dragover', (e) => self._onDragOver(e));
        el.addEventListener('dragleave', (e) => self._onDragLeave(e));
        el.addEventListener('drop', (e) => self._onDrop(e));
        el.addEventListener('dragend', (e) => self._onDragEnd(e));
      };
      bindDrag(card);
      if (this.opts.bindInnerDragTargets) {
        card.querySelectorAll('img, .sj-media-image-original, .sj-media-image-desc').forEach((n) => {
          n.setAttribute('draggable', 'true');
          bindDrag(n);
        });
      }
    }

    return card;
  };

  MainImageGrid.prototype._createFabricCard = function (item, fcOpts) {
    const C = Card();
    const rawName = String(item.image_name || '');
    const safeName = escapeAttr(rawName);
    const card = document.createElement('div');
    card.className = (C && C.buildCardClassName)
      ? C.buildCardClassName(item, 'sj-media-image-card--static')
      : 'sj-media-image-card sj-media-image-card--static';
    card.setAttribute('draggable', 'false');
    const infoHtml = (C && C.buildInfoHtml)
      ? C.buildInfoHtml(item, Object.assign({}, fcOpts, { readonly: true }))
      : '';
    const preview = this.previewUrl(item);
    const previewHtml = preview
      ? `<img src="${escapeAttr(preview)}" alt="${safeName}" class="sj-media-image-preview" loading="lazy">`
      : '<div style="width:100%;height:100%;border:1px dashed var(--morandi-sand);border-radius:12px;background:rgba(0,0,0,0.02);"></div>';
    card.innerHTML = `
      <div class="sj-fabric-badge-anchor"><span class="sj-fabric-badge">面料</span></div>
      <div class="sj-media-image-preview-wrap">${previewHtml}</div>
      ${infoHtml}`;
    return card;
  };

  MainImageGrid.prototype._bindStatusSegments = function (grid) {
    const self = this;
    const C = Card();
    if (!C || typeof C.bindStatusSegments !== 'function') return;
    C.bindStatusSegments(grid, {
      rerender: () => self.render(),
      onEnabledChange: async ({ pathB64, enabled }) => {
        if (typeof self.opts.onEnabledChange === 'function') {
          await self.opts.onEnabledChange({ pathB64, enabled });
          return;
        }
        const resp = await fetch('/api/gallery-image-meta', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: pathB64, is_enabled: enabled ? 1 : 0 }),
        });
        const data = await resp.json();
        if (!data || data.status !== 'success') {
          throw new Error((data && data.message) ? data.message : '保存失败');
        }
        if (typeof self.opts.updateItemEnabled === 'function') {
          self.opts.updateItemEnabled(pathB64, enabled);
        }
        if (typeof self.opts.onEnabledSuccess === 'function') {
          self.opts.onEnabledSuccess(enabled);
        } else if (global.showAppToast) {
          global.showAppToast(enabled ? '已启用' : '已弃用', false, 3000);
        }
      },
    });
  };

  MainImageGrid.prototype._onDragStart = function (e) {
    const card = (e.currentTarget && e.currentTarget.closest)
      ? e.currentTarget.closest('.sj-media-image-card')
      : e.currentTarget;
    if (!card || card.classList.contains('placeholder')) return;
    this._dragIdx = parseInt(card.dataset.index || '0', 10);
    this._dragInsert = this._dragIdx;
    card.classList.add('dragging');
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', String(this._dragIdx)); } catch (_e) {}
    }
    if (typeof this.opts.onDragStart === 'function') {
      this.opts.onDragStart(e, card);
    }
  };

  MainImageGrid.prototype._onDragEnter = function (e) {
    e.preventDefault();
    const card = e.currentTarget;
    if (!card || card.classList.contains('placeholder')) return;
    card.classList.add('drag-over');
  };

  MainImageGrid.prototype._onDragOver = function (e) {
    e.preventDefault();
    this._updateDragPlaceholder(e.clientX, e.clientY);
  };

  MainImageGrid.prototype._onDragLeave = function (e) {
    const card = e.currentTarget;
    if (card) card.classList.remove('drag-over');
  };

  MainImageGrid.prototype._onDragLeaveGrid = function (e) {
    const grid = this.getGridEl();
    if (!grid) return;
    if (e.relatedTarget && grid.contains(e.relatedTarget)) return;
    const placeholder = grid.querySelector('.sj-media-image-card.placeholder');
    if (placeholder) placeholder.style.display = 'none';
  };

  MainImageGrid.prototype._updateDragPlaceholder = function (clientX, clientY) {
    const grid = this.getGridEl();
    const placeholder = grid && grid.querySelector('.sj-media-image-card.placeholder');
    if (!grid || !placeholder) return;
    const cards = Array.from(grid.children).filter((n) =>
      n.classList && n.classList.contains('sj-media-image-card') && !n.classList.contains('placeholder')
      && n.getAttribute('draggable') === 'true'
    );
    if (!cards.length) {
      this._dragInsert = 0;
      placeholder.style.display = '';
      grid.appendChild(placeholder);
      return;
    }
    let insertIndex = cards.length;
    const pointed = document.elementFromPoint(clientX, clientY);
    const pointedCard = pointed && pointed.closest ? pointed.closest('.sj-media-image-card') : null;
    if (pointedCard && !pointedCard.classList.contains('placeholder') && grid.contains(pointedCard)
      && pointedCard.getAttribute('draggable') === 'true') {
      const targetIndex = parseInt(pointedCard.dataset.index || '0', 10);
      const rect = pointedCard.getBoundingClientRect();
      const before = clientY < (rect.top + rect.height / 2);
      insertIndex = before ? targetIndex : targetIndex + 1;
    } else if (this.opts.dragPlaceholderVerticalFallback) {
      for (let i = 0; i < cards.length; i++) {
        const r = cards[i].getBoundingClientRect();
        const mid = r.top + r.height / 2;
        if (clientY < mid) {
          insertIndex = i;
          break;
        }
      }
    }
    insertIndex = Math.max(0, Math.min(cards.length, insertIndex));
    this._dragInsert = insertIndex;
    placeholder.style.display = '';
    if (insertIndex >= cards.length) grid.appendChild(placeholder);
    else grid.insertBefore(placeholder, cards[insertIndex]);
  };

  MainImageGrid.prototype._reorderSourceArray = function (fromIndex, insertIndex, viewList) {
    const items = (this.opts.getItems ? this.opts.getItems() : []) || [];
    const list = viewList || this.getViewList();
    if (fromIndex < 0 || fromIndex >= list.length) return;
    const moved = list[fromIndex];
    const sourceFrom = items.indexOf(moved);
    if (sourceFrom < 0) return;
    let targetSource;
    if (insertIndex >= list.length) {
      targetSource = items.length;
    } else {
      targetSource = items.indexOf(list[insertIndex]);
      if (targetSource < 0) targetSource = items.length;
    }
    const item = items.splice(sourceFrom, 1)[0];
    if (targetSource > sourceFrom) targetSource -= 1;
    items.splice(targetSource, 0, item);
    items.forEach((it, idx) => {
      if (it && typeof it === 'object') it.sort_order = idx;
    });
  };

  MainImageGrid.prototype._onDrop = function (e) {
    e.preventDefault();
    const grid = this.getGridEl();
    const placeholder = grid && grid.querySelector('.sj-media-image-card.placeholder');
    if (placeholder) placeholder.style.display = 'none';

    const viewList = this.getViewList();
    if (this._dragIdx === null || this._dragIdx === undefined) return;
    if (this._dragIdx < 0 || this._dragIdx >= viewList.length) return;
    let insertIndex = (this._dragInsert === null || this._dragInsert === undefined)
      ? viewList.length : this._dragInsert;
    insertIndex = Math.max(0, Math.min(viewList.length, insertIndex));

    if (typeof this.opts.applyReorder === 'function') {
      this.opts.applyReorder({
        fromIndex: this._dragIdx,
        insertIndex,
        viewList: viewList.slice(),
      });
      this._dragIdx = null;
      this._dragInsert = null;
      this.render();
      return;
    }

    if (this.opts.reorderMode === 'sourceArray') {
      this._reorderSourceArray(this._dragIdx, insertIndex, viewList);
      this._dragIdx = null;
      this._dragInsert = null;
      this.render();
      if (typeof this.opts.onReorder === 'function') {
        this.opts.onReorder(viewList, this.opts.getItems ? this.opts.getItems() : []);
      }
      return;
    }

    const moved = viewList.splice(this._dragIdx, 1)[0];
    if (insertIndex > this._dragIdx) insertIndex -= 1;
    viewList.splice(insertIndex, 0, moved);

    const items = (this.opts.getItems ? this.opts.getItems() : []) || [];
    const keyFn = (it) => this.itemKey(it);
    const keyToIdx = new Map();
    items.forEach((it, idx) => keyToIdx.set(keyFn(it), idx));
    viewList.forEach((it, idx) => {
      const origIdx = keyToIdx.get(keyFn(it));
      if (origIdx !== undefined) items[origIdx].sort_order = idx + 1;
    });

    this._dragIdx = null;
    this._dragInsert = null;
    this.render();
    if (typeof this.opts.onReorder === 'function') {
      this.opts.onReorder(viewList, items);
    }
  };

  MainImageGrid.prototype._onDragEnd = function (e) {
    const grid = this.getGridEl();
    if (grid) {
      grid.querySelectorAll('.sj-media-image-card').forEach((c) => c.classList.remove('dragging', 'drag-over'));
    }
    this._dragIdx = null;
    this._dragInsert = null;
    const placeholder = grid && grid.querySelector('.sj-media-image-card.placeholder');
    if (placeholder) placeholder.style.display = 'none';
    if (typeof this.opts.onDragEnd === 'function') {
      this.opts.onDragEnd(e);
    }
  };

  MainImageGrid.prototype._bindDrag = function (grid, placeholder) {
    const self = this;
    grid.ondragover = (e) => {
      e.preventDefault();
      self._updateDragPlaceholder(e.clientX, e.clientY);
    };
    grid.ondrop = (e) => self._onDrop(e);
    grid.ondragleave = (e) => self._onDragLeaveGrid(e);
  };

  global.SitjoyMainImageGrid = {
    create(options) {
      return new MainImageGrid(options);
    },
  };
})(window);

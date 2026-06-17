/**
 * 「选择已有图片」：薄封装，统一走 SitjoyNasBrowseModal（与云端关联同布局）。
 * 用法：SjPickExistingImages.open({ context, fabricId, variantId, orderProductId, title, onConfirm(items) })
 */
(function (global) {
  const api = { open: null, close: null, loadList: null };
  global.SjPickExistingImages = api;

  function modal() {
    return global.SitjoyNasBrowseModal || null;
  }

  async function open(opts) {
    const M = modal();
    if (!M || typeof M.open !== 'function') {
      if (global.showAppToast) global.showAppToast('选择已有图片组件未加载，请刷新页面', true, 8000);
      return;
    }
    const context = String(opts?.context || 'fabric').trim().toLowerCase();
    await M.open({
      profile: 'pick',
      title: opts?.title || '选择已有图片',
      helpTip: '仅显示当前目录下、尚未绑定到所选面料/SKU/规格的图片。文件夹请双击进入。',
      context: context,
      dataSource: context === 'fabric' ? 'fabric-images' : 'image-picker',
      fabricId: opts?.fabricId || opts?.fabric_id || null,
      fabricCode: opts?.fabricCode || opts?.fabric_code || '',
      variantId: opts?.variantId || opts?.variant_id || opts?.salesProductId || null,
      salesProductId: opts?.salesProductId || opts?.sales_product_id || null,
      orderProductId: opts?.orderProductId || opts?.order_product_id || null,
      getImageTypeOptions: opts?.getImageTypeOptions || null,
      getImportImageType: opts?.getImportImageType || null,
      onConfirm: opts?.onConfirm || null,
    });
  }

  function close() {
    const M = modal();
    if (M && typeof M.close === 'function') M.close();
  }

  function loadList() {
    const M = modal();
    if (M && typeof M.reload === 'function') return M.reload();
    return Promise.resolve();
  }

  api.open = open;
  api.close = close;
  api.loadList = loadList;
})(typeof window !== 'undefined' ? window : this);

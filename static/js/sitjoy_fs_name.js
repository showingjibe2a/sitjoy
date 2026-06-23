/**
 * 文件系统文件名 Base64 ↔ 展示名（与后端 _decode_fs_name_bytes / name_raw_b64 配套）。
 */
(function (global) {
  function b64ToBytes(b64) {
    try {
      const binary = atob(String(b64 || '').trim());
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch (e) {
      return null;
    }
  }

  function decodeFsNameFromB64(rawB64) {
    if (!rawB64) return '';
    const bytes = b64ToBytes(rawB64);
    if (!bytes || !bytes.length) return '';
    const encs = ['utf-8', 'gb18030', 'gbk', 'iso-8859-1'];
    for (let i = 0; i < encs.length; i++) {
      const enc = encs[i];
      try {
        if (typeof TextDecoder !== 'undefined') {
          const dec = new TextDecoder(enc, { fatal: false }).decode(bytes);
          if (dec && dec.indexOf('\uFFFD') === -1) return dec;
        }
      } catch (e) {
        continue;
      }
    }
    let s = '';
    for (let j = 0; j < bytes.length; j++) s += String.fromCharCode(bytes[j]);
    return s;
  }

  function encodeUtf8ToB64(text) {
    const s = String(text || '');
    if (!s) return '';
    if (typeof TextEncoder !== 'undefined') {
      const bytes = new TextEncoder().encode(s);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    }
    return btoa(unescape(encodeURIComponent(s)));
  }

  function resolveItemDisplayName(item) {
    const it = item || {};
    const raw = String(it.name_raw_b64 || it.rawB64 || '').trim();
    if (raw) {
      const decoded = decodeFsNameFromB64(raw);
      if (decoded) return decoded;
    }
    const display = String(it.display || '').trim();
    if (display) return display;
    const name = String(it.name || '').trim();
    if (!name) return '';
    if (/^[A-Za-z0-9+/=]+$/.test(name) && name.length >= 4) {
      const decoded = decodeFsNameFromB64(name);
      if (decoded) return decoded;
    }
    return name;
  }

  global.SitjoyFsName = {
    b64ToBytes: b64ToBytes,
    decodeFsNameFromB64: decodeFsNameFromB64,
    encodeUtf8ToB64: encodeUtf8ToB64,
    resolveItemDisplayName: resolveItemDisplayName,
  };
})(typeof window !== 'undefined' ? window : this);

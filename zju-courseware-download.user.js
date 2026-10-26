// ==UserScript==
// @name         学在浙大 · 下载课件（含 WPS 导出）
// @namespace    https://courses.zju.edu.cn/
// @version      2.0.2
// @description  在学习活动页加“下载课件”按钮。普通附件走正常接口；老师禁止下载的附件，参照 zju-learning-assistant 走 WPS 预览导出协议（原文件 > 预览版 PDF）。仅用于下载自己选修课程的课件。
// @author       based on PeiPei233/zju-learning-assistant
// @match        https://courses.zju.edu.cn/course/*/learning-activity*
// @require      https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.3.2/jsencrypt.min.js
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      courses.zju.edu.cn
// @connect      course-wps.zju.edu.cn
// @connect      zju.edu.cn
// @run-at       document-idle
// ==/UserScript==

/* global JSEncrypt */
(function () {
  'use strict';

  const MARK = 'data-zju-dl';
  const enc = (s) => new TextEncoder().encode(s);
  // 加了 @grant 后脚本在沙箱里运行，页面全局（angular）需经 unsafeWindow 访问
  const PAGE = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;

  // ---------- 基础工具 ----------
  function randAlnum(n) {
    const cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    let s = '';
    for (let i = 0; i < n; i++) s += cs[a[i] % cs.length];
    return s;
  }
  function bytesToB64(buf) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function b64ToBytes(b64) {
    const s = atob(b64.trim());
    const a = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }

  // ---------- 加密：AES-256-CBC (PKCS7) + RSA PKCS1v1.5 ----------
  async function aesEncrypt(keyBytes, ivBytes, dataBytes) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, k, dataBytes);
    return bytesToB64(ct);
  }
  async function aesDecrypt(keyBytes, ivBytes, b64str) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, k, b64ToBytes(b64str));
    return new TextDecoder().decode(pt);
  }
  // publicKeyB64 是 PEM 文本的 base64 编码
  function rsaEncrypt(publicKeyB64, plaintext) {
    const pem = atob(publicKeyB64);
    const e = new JSEncrypt();
    e.setPublicKey(pem);
    const out = e.encrypt(plaintext); // 默认 PKCS1 v1.5，返回 base64 或 false
    if (!out) throw new Error('WPS 公钥加密失败');
    return out;
  }

  // ---------- 跨域请求 ----------
  function gm(opts) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        ...opts,
        onload: resolve,
        onerror: () => reject(new Error('网络请求失败')),
        ontimeout: () => reject(new Error('请求超时')),
      });
    });
  }
  function headerMap(raw) {
    const m = {};
    (raw || '').trim().split(/\r?\n/).forEach((line) => {
      const i = line.indexOf(':');
      if (i > 0) m[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    });
    return m;
  }

  // ---------- 解析 WPS 预览页里的 __WPSENV__ ----------
  function parseWpsEnv(html, uploadId) {
    const marker = 'window.__WPSENV__=';
    const at = html.indexOf(marker);
    if (at < 0) throw new Error('WPS 预览页面格式已变化或登录已过期');
    let i = html.indexOf('{', at);
    if (i < 0) throw new Error('WPS 预览配置为空');
    // 括号配对（跳过字符串与转义），截取第一个完整 JSON 对象
    let depth = 0, inStr = false, escp = false, end = -1;
    for (let j = i; j < html.length; j++) {
      const c = html[j];
      if (inStr) {
        if (escp) escp = false;
        else if (c === '\\') escp = true;
        else if (c === '"') inStr = false;
      } else {
        if (c === '"') inStr = true;
        else if (c === '{') depth++;
        else if (c === '}') { depth--; if (depth === 0) { end = j + 1; break; } }
      }
    }
    if (end < 0) throw new Error('无法读取 WPS 预览配置');
    const boot = JSON.parse(html.slice(i, end));
    if (String(boot.root_file_id) !== String(uploadId)) throw new Error('WPS 返回的课件与请求不一致');
    const e = boot.encryption || {};
    if (!e.isEncryption || e.algorithm !== 'AES256') throw new Error('WPS 加密协议已变化，脚本需更新');
    return boot;
  }

  // ---------- 取 WPS 预览地址（同源接口）----------
  async function getPreviewUrl(uploadId, activityId) {
    const ep = `/api/uploads/${uploadId}/preview/private-wps?preview=true`
      + `&refer_id=${activityId}&refer_type=learning_activity`;
    const r = await fetch(ep, { credentials: 'same-origin' });
    if (!r.ok) throw new Error(`获取 WPS 预览地址失败 (HTTP ${r.status})`);
    const info = await r.json();
    if (!info.preview_url) throw new Error('此课件未提供 WPS 预览地址');
    return info.preview_url;
  }

  function hostAllowed(u, host) {
    try { const x = new URL(u); return x.protocol === 'https:' && (host ? x.hostname === host : (x.hostname === 'zju.edu.cn' || x.hostname.endsWith('.zju.edu.cn'))); }
    catch (e) { return false; }
  }

  // ---------- WPS 导出：mode = 'original' | 'pdf' ----------
  async function wpsExport(uploadId, activityId, mode) {
    const previewUrl0 = await getPreviewUrl(uploadId, activityId);
    if (!hostAllowed(previewUrl0, 'course-wps.zju.edu.cn')) throw new Error('WPS 预览地址不属于学在浙大');

    const page = await gm({ method: 'GET', url: previewUrl0, timeout: 30000 });
    if (page.status < 200 || page.status >= 300) throw new Error(`打开 WPS 预览页失败 (HTTP ${page.status})`);
    const previewUrl = page.finalUrl || previewUrl0;
    if (!hostAllowed(previewUrl, 'course-wps.zju.edu.cn')) throw new Error('WPS 预览地址不属于学在浙大');
    const boot = parseWpsEnv(page.responseText, uploadId);

    const keyStr = randAlnum(32), ivStr = randAlnum(16);
    const keyBytes = enc(keyStr), ivBytes = enc(ivStr);
    const wrapped = rsaEncrypt(boot.encryption.publicKey, JSON.stringify({ private_key: keyStr, iv: ivStr }));

    const action = mode === 'original' ? 'download' : 'export';
    const httpMethod = mode === 'original' ? 'GET' : 'POST';
    const apiObj = {
      method: httpMethod,
      api: `/api/v3/office/file/${boot.root_file_id}/${action}`,
      query_string: '', schema: 'https',
    };
    const apiParam = await aesEncrypt(keyBytes, ivBytes, enc(JSON.stringify(apiObj)));

    const pv = new URL(previewUrl);
    const gatewayUrl = new URL(boot.encryption.gateway, previewUrl).href;
    if (!hostAllowed(gatewayUrl, 'course-wps.zju.edu.cn')) throw new Error('WPS 网关地址异常');

    const body = mode === 'original'
      ? ''
      : await aesEncrypt(keyBytes, ivBytes, enc(JSON.stringify({ format: 'pdf', options: {}, print: true, clientId: '', password: '' })));

    const resp = await gm({
      method: 'POST',
      url: gatewayUrl,
      data: body,
      timeout: 90000,
      headers: {
        'content-type': 'application/json',
        'origin': pv.origin,
        'referer': previewUrl,
        'x-app-id': boot.app_id,
        'x-csrf-rand': boot.csrf_token,
        'x-user-query': pv.search.replace(/^\?/, ''),
        'encryption-algorithm': 'AES256',
        'encryption-parameters': wrapped,
        'api-parameters': apiParam,
      },
    });
    if (resp.status < 200 || resp.status >= 300) throw new Error(`WPS 导出失败 (HTTP ${resp.status})`);

    const encrypted = headerMap(resp.responseHeaders)['encryption'] === '1';
    const plaintext = encrypted ? await aesDecrypt(keyBytes, ivBytes, resp.responseText) : resp.responseText;
    const data = JSON.parse(plaintext);
    const dlUrl = data.url || (data.data && data.data.url);
    if (!dlUrl) throw new Error('WPS 未提供导出文件（可能没有打印权限或文件未就绪）');
    if (!hostAllowed(dlUrl)) throw new Error('WPS 导出地址不属于浙江大学，已停止下载');

    const file = await gm({ method: 'GET', url: dlUrl, responseType: 'blob', timeout: 180000, headers: { 'referer': previewUrl } });
    if (file.status < 200 || file.status >= 300) throw new Error(`导出文件下载失败 (HTTP ${file.status})，请重试`);
    return file.response; // Blob
  }

  // ---------- 普通附件直连接口 ----------
  async function tryBlob(url) {
    const r = await fetch(url, { credentials: 'same-origin' });
    const ct = r.headers.get('content-type') || '';
    // 登录过期时会返回 200 的 HTML 登录页，不能当课件存下来
    if (r.ok && !ct.includes('application/json') && !ct.includes('text/html')) return await r.blob();
    return null;
  }

  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // ---------- 下载一个附件：先直连，失败再 WPS ----------
  async function downloadUpload(upload, activityId, setStatus) {
    const name = upload.name || String(upload.id);
    // 1. reference/blob
    setStatus('下载中…');
    let blob = await tryBlob(`/api/uploads/reference/${upload.reference_id}/blob`).catch(() => null);
    // 2. uploads/{id}/blob
    if (!blob) blob = await tryBlob(`/api/uploads/${upload.id}/blob`).catch(() => null);
    if (blob) { saveBlob(blob, name); setStatus('✓ 已下载'); return; }

    if (!upload.allow_private_wps_office_view) {
      throw new Error('老师未开放下载，且该课件不支持 WPS 导出');
    }
    // 3. WPS 导出原文件
    setStatus('WPS 导出原文件…');
    try {
      const b = await wpsExport(upload.id, activityId, 'original');
      saveBlob(b, name); setStatus('✓ 已下载（WPS 原文件）'); return;
    } catch (e1) {
      // 4. WPS 导出预览版 PDF
      setStatus('导出预览版 PDF…');
      let b;
      try { b = await wpsExport(upload.id, activityId, 'pdf'); }
      catch (e2) { throw new Error(`原文件：${e1.message}；预览版 PDF：${e2.message}`); }
      saveBlob(b, name + '.preview.pdf'); setStatus('✓ 已下载（预览版 PDF）'); return;
    }
  }

  // ---------- 页面注入 ----------
  function getUpload(el) {
    try { const s = PAGE.angular && PAGE.angular.element(el).scope(); return s && s.upload && s.upload.id ? s.upload : null; }
    catch (e) { return null; }
  }
  function collectUploads() {
    const list = [], seen = new Set();
    document.querySelectorAll('.file-name').forEach((el) => {
      const u = getUpload(el);
      if (u && !seen.has(u.id)) { seen.add(u.id); list.push({ el, upload: u }); }
    });
    return list;
  }
  function currentActivityId() {
    const m = location.hash.match(/\/(\d+)/);
    return m ? m[1] : null;
  }
  function makeBtn(text) {
    const b = document.createElement('a');
    b.href = 'javascript:void(0)';
    b.textContent = text;
    b.style.cssText = 'display:inline-block;font-size:14px;cursor:pointer;color:#1aaa55;text-decoration:none;white-space:nowrap;';
    return b;
  }

  function inject() {
    const items = collectUploads();
    if (!items.length) return;

    items.forEach(({ el, upload }) => {
      // 优先放进该行的“操作”列；文件名行带截断样式，塞进去会把文件名挤成“第....pdf”
      const row = el.closest('.attachment-row');
      const ops = row && row.querySelector('.attachment-operations');
      const host = ops || el.closest('.file-info') || el.parentElement;
      if (!host || host.querySelector(`[${MARK}="item"]`)) return;
      // 老师已开放下载时页面自带“下载”按钮，不再重复加
      if (ops && ops.textContent.includes('下载')) return;
      const b = makeBtn('⬇ 下载');
      if (ops) b.style.marginLeft = '8px';
      else { b.style.display = 'block'; b.style.marginTop = '2px'; }
      b.setAttribute(MARK, 'item');
      const setStatus = (t) => { b.textContent = t; };
      b.addEventListener('click', async (ev) => {
        ev.stopPropagation(); ev.preventDefault();
        b.style.pointerEvents = 'none';
        // 活动 ID 在点击时取：单页应用切换活动后，旧按钮可能被保留下来
        try { await downloadUpload(upload, currentActivityId(), setStatus); }
        catch (e) { setStatus('✗ 失败'); alert(`「${upload.name}」下载失败：${e.message}`); }
        finally { setTimeout(() => { b.textContent = '⬇ 下载'; b.style.pointerEvents = ''; }, 2500); }
      });
      host.appendChild(b);
    });

    // 整个附件列表块（.attachments-wrapper）之前；找不到就不放，免得插进文件名行里
    const table = items[0].el.closest('.attachments-wrapper') || items[0].el.closest('table') || items[0].el.closest('.attachments');
    const container = table && table.parentElement;
    if (!container || container.querySelector(`[${MARK}="all"]`)) return;
    const bar = document.createElement('div');
    bar.setAttribute(MARK, 'all');
    bar.style.cssText = 'margin:16px 0 4px 0;padding-left:25px;'; // 与“附件名”表头文字对齐
    const all = makeBtn('☁ 下载课件');
    all.style.fontSize = '16px';
    all.addEventListener('click', async (ev) => {
      ev.preventDefault();
      all.style.pointerEvents = 'none';
      const list = collectUploads().map((x) => x.upload);
      const activityId = currentActivityId();
      const fails = [];
      for (const u of list) {
        const name = u.name || String(u.id);
        all.textContent = `☁ 下载中：${name.slice(0, 16)}…`;
        try { await downloadUpload(u, activityId, () => {}); }
        catch (e) { fails.push(`${name}：${e.message}`); }
      }
      all.textContent = '☁ 下载课件';
      all.style.pointerEvents = '';
      if (fails.length) alert('以下课件下载失败：\n' + fails.map((s) => '· ' + s).join('\n'));
    });
    bar.appendChild(all);
    container.insertBefore(bar, table);
  }

  let timer = null;
  // 节流而不是防抖：页面有持续 DOM 变动（视频进度、动画）时防抖会一直被推迟，按钮永远加不上
  new MutationObserver(() => { if (!timer) timer = setTimeout(() => { timer = null; inject(); }, 300); })
    .observe(document.body, { childList: true, subtree: true });
  inject();
})();

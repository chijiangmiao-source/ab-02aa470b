"""HTTP 服务：版本选择、序列号查询、批次提交与证明复算。

仅依赖 Python 标准库。页面与 JSON API 同源提供。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import hashing as H
from .store import BatchError, StaleRootError, Store, verify_proof

DB_PATH = os.environ.get("APP_DB", "/data/directory.db")


def _proof_response(store: Store, version: int, serial: int) -> tuple[dict, int]:
    try:
        proof = store.proof(version, serial)
    except BatchError as exc:
        return {"error": exc.code, "message": str(exc)}, 404
    recomputed, valid = verify_proof(proof)
    body = proof.to_dict(recomputed, valid)
    body["levels"] = [
        {
            "depth": i + 1,
            "direction": "right" if proof.path[i] else "left",
            "sibling": proof.siblings[i].hex(),
        }
        for i in range(H.TREE_LEVELS)
    ]
    return body, 200


PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>十六层稀疏 Merkle 吊销目录</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 -apple-system, "Segoe UI", "PingFang SC",
         "Microsoft YaHei", sans-serif; margin: 0; padding: 24px;
         max-width: 980px; margin-inline: auto; }
  h1 { font-size: 20px; }
  h2 { font-size: 16px; margin-top: 32px; }
  fieldset { border: 1px solid #8884; border-radius: 8px; padding: 16px;
             margin: 16px 0; }
  legend { padding: 0 6px; font-weight: 600; }
  label { display: inline-block; margin-right: 12px; }
  input, select, button, textarea { font: inherit; padding: 6px 8px; }
  input[type=text], select { min-width: 140px; }
  button { cursor: pointer; border-radius: 6px; border: 1px solid #8888;
           background: #2b6cb0; color: #fff; padding: 8px 18px; }
  button.secondary { background: #555; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; }
  th, td { border: 1px solid #8886; padding: 5px 8px; text-align: left;
           font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
           font-size: 12px; word-break: break-all; }
  th { background: #8882; }
  .ok { color: #15803d; font-weight: 700; }
  .bad { color: #b91c1c; font-weight: 700; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; }
  .muted { color: #888; }
  pre { white-space: pre-wrap; word-break: break-all; background: #8881;
        padding: 10px; border-radius: 6px; }
  .pill { display: inline-block; padding: 2px 10px; border-radius: 999px;
          font-size: 12px; }
  .pill.revoked { background: #b91c1c22; color: #b91c1c; }
  .pill.active { background: #15803d22; color: #15803d; }
</style>
</head>
<body>
<h1>地面设备短序列号吊销目录（版本化稀疏 Merkle 树）</h1>
<p class="muted">叶子 SHA256(0x00‖serial(2B)‖status) · 分支 SHA256(0x01‖L‖R) ·
空叶 SHA256(0x02) · 固定 16 层，路径自高位到低位。查询始终针对所选<em>已发布版本</em>，
后续批次不改变旧版本结果。</p>

<fieldset>
<legend>按版本查询序列号</legend>
<label>版本
  <select id="version"></select>
</label>
<label>序列号（四位十六进制）
  <input id="serial" type="text" maxlength="4" placeholder="0000..FFFF">
</label>
<button id="query">查询并复算</button>
<div id="result"></div>
</fieldset>

<fieldset>
<legend>提交吊销 / 解除批次（至多 32 项）</legend>
<p class="muted">仅当“操作员看到的目录根”等于当前最新根时才会生成新版本，
否则返回 409 陈旧根冲突且不产生版本。</p>
<label>期望根（最新根 hex）
  <input id="root" type="text" style="min-width:520px" placeholder="64 hex chars">
</label>
<button id="useroot" type="button" class="secondary">填入当前最新根</button><br><br>
<textarea id="items" rows="6" style="width:100%; box-sizing:border-box"
  placeholder='[{"serial":"00A1","status":"revoked"},{"serial":"FF00","status":"released"}]'></textarea><br><br>
<button id="submit">提交批次</button>
<div id="submitResult"></div>
</fieldset>

<h2>已发布版本</h2>
<div id="versionList"></div>

<script>
const $ = (id) => document.getElementById(id);

async function loadVersions(selectVersion) {
  const res = await fetch('/api/versions');
  const data = await res.json();
  const sel = $('version');
  sel.innerHTML = '';
  for (const v of data.versions) {
    const opt = document.createElement('option');
    opt.value = v.version;
    opt.textContent = 'v' + v.version + (v.note ? ' — ' + v.note : '');
    sel.appendChild(opt);
  }
  sel.value = String(data.latest.version);
  $('root').value = data.latest.root;
  $('versionList').innerHTML = '<table><tr><th>版本</th><th>根</th>'
    + '<th>条目数</th><th>发布时间(UTC)</th><th>备注</th></tr>'
    + data.versions.map(v => '<tr><td>v' + v.version + '</td><td class=mono>'
      + v.root + '</td><td>' + (v.item_count ?? 0) + '</td><td>'
      + v.created_at + '</td><td>' + (v.note ?? '') + '</td></tr>').join('')
    + '</table>';
  if (selectVersion !== undefined) sel.value = String(selectVersion);
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

async function sha256(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(h);
}
function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++)
    b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
function bytesToHex(b) {
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

// 浏览器本地按同一摘要规范复算：branch = SHA256(0x01||L||R)
async function browserRecompute(d, tamperLayer) {
  let node = hexToBytes(d.leaf_digest);
  for (let i = d.siblings.length - 1; i >= 0; i--) {
    let sibHex = d.siblings[i];
    if (tamperLayer === i + 1) {
      const bytes = hexToBytes(sibHex);
      bytes[0] ^= 0xff;  // 篡改该层兄弟摘要第一个字节
      sibHex = bytesToHex(bytes);
    }
    const sib = hexToBytes(sibHex);
    const buf = new Uint8Array(1 + 32 + 32);
    buf[0] = 0x01;
    if (d.path_bits[i] === 0) { buf.set(node, 1); buf.set(sib, 33); }
    else { buf.set(sib, 1); buf.set(node, 33); }
    node = await sha256(buf);
  }
  return bytesToHex(node);
}

async function query() {
  const version = $('version').value;
  const serial = $('serial').value.trim();
  if (!/^[0-9a-fA-F]{1,4}$/.test(serial)) {
    $('result').innerHTML = '<p class=bad>请输入 1..4 位十六进制序列号</p>';
    return;
  }
  const res = await fetch('/api/proof?version=' + encodeURIComponent(version)
    + '&serial=' + encodeURIComponent(serial));
  const d = await res.json();
  if (!res.ok) {
    $('result').innerHTML = '<p class=bad>' + esc(d.message || 'error') + '</p>';
    return;
  }
  // 本地（浏览器）独立复算，不采用服务端 recomputed 字段
  const localRoot = await browserRecompute(d, null);
  const localOk = localRoot === d.root;
  const rows = d.levels.map(l => '<tr><td>' + l.depth + '</td><td>'
    + (l.direction === 'left' ? '0（向左）' : '1（向右）') + '</td><td>'
    + esc(l.sibling) + '</td></tr>').join('');
  $('result').innerHTML =
    '<table><tr><th>版本根</th><td class=mono>' + esc(d.root) + '</td></tr>'
    + '<tr><th>序列号</th><td class=mono>' + esc(d.serial) + '</td></tr>'
    + '<tr><th>状态</th><td><span class="pill ' + d.status + '">'
      + (d.status === 'revoked' ? '已吊销（包含证明）' : '未吊销（未包含证明）')
      + '</span></td></tr>'
    + '<tr><th>叶子摘要</th><td class=mono>' + esc(d.leaf_digest) + '</td></tr>'
    + '<tr><th>浏览器本地复算根</th><td class=mono>' + esc(localRoot)
      + '</td></tr>'
    + '<tr><th>本地复算结论</th><td class="' + (localOk ? 'ok' : 'bad')
      + '">' + (localOk ? '✓ 与版本根一致，证明有效'
        : '✗ 与版本根不一致，证明校验失败') + '</td></tr>'
    + '<tr><th>服务端复算（对照）</th><td class=mono>'
      + esc(d.recomputed_root) + ' · '
      + (d.root_check_ok ? '一致' : '不一致') + '</td></tr></table>'
    + '<p><button id="tamper" type="button" class="secondary">篡改第 8 层兄弟摘要后本地复算</button></p>'
    + '<div id="tamperResult"></div>'
    + '<table><tr><th>层（高→低）</th><th>路径位</th><th>兄弟摘要</th></tr>'
    + rows + '</table>';
  $('tamper').onclick = async () => {
    const tamperedRoot = await browserRecompute(d, 8);
    const ok = tamperedRoot === d.root;
    $('tamperResult').innerHTML =
      '<p class="' + (ok ? 'ok' : 'bad') + '">篡改第 8 层兄弟摘要后本地复算根 = '
      + '<span class=mono>' + esc(tamperedRoot) + '</span>，'
      + (ok ? '仍与版本根一致（不应发生！）'
            : '与版本根不一致 → 根校验失败，篡改可观察。') + '</p>';
  };
}

async function submitBatch() {
  $('submitResult').textContent = '提交中…';
  let items;
  try { items = JSON.parse($('items').value); }
  catch (e) {
    $('submitResult').innerHTML = '<p class=bad>items 不是合法 JSON</p>';
    return;
  }
  const res = await fetch('/api/batches', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({expected_root: $('root').value, items})
  });
  const d = await res.json();
  if (!res.ok) {
    $('submitResult').innerHTML = '<p class=bad>HTTP ' + res.status + ' · '
      + esc(d.error || '') + '：' + esc(d.message || '')
      + '</p><pre>' + esc(JSON.stringify(d, null, 2)) + '</pre>'
      + '<p class=muted>未生成新版本。</p>';
    return;
  }
  $('submitResult').innerHTML = '<p class=ok>已生成 v' + d.version
    + '，新根 ' + esc(d.root) + '</p><pre>'
    + esc(JSON.stringify(d.proofs.map(p => ({
        serial: p.serial, status: p.status, included: p.included,
        root_check_ok: p.root_check_ok})), null, 2)) + '</pre>';
  await loadVersions(d.version);
  $('root').value = d.root;
}

$('query').onclick = query;
$('submit').onclick = submitBatch;
$('useroot').onclick = () => loadVersions();
$('serial').addEventListener('keydown', e => { if (e.key === 'Enter') query(); });
loadVersions();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "RevocationDir/1.0"

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    def _send_json(self, payload, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html: str, status: int = 200) -> None:
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args) -> None:  # 安静日志
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/health":
                latest = self.store.latest()
                self._send_json({
                    "status": "ok",
                    "latest_version": latest["version"],
                    "latest_root": latest["root"],
                    "tree_levels": H.TREE_LEVELS,
                })
            elif path == "/api/versions":
                versions = self.store.versions()
                latest = self.store.latest()
                self._send_json({"latest": latest, "versions": versions})
            elif path.startswith("/api/version/"):
                try:
                    version = int(path.rsplit("/", 1)[1])
                except ValueError:
                    self._send_json({"error": "BAD_REQUEST",
                                     "message": "version must be an integer"},
                                    400)
                    return
                v = self.store.version(version)
                if v is None:
                    self._send_json({"error": "VERSION_NOT_FOUND",
                                     "message": f"version {version} not found"},
                                    404)
                    return
                self._send_json({"version": v, "batch": self.store.batch(version)})
            elif path == "/api/proof":
                q = parse_qs(parsed.query)
                try:
                    version = int(q["version"][0])
                    serial = int(q["serial"][0], 16)
                    if not 0 <= version or not 0 <= serial <= 0xFFFF:
                        raise ValueError
                except (KeyError, ValueError, IndexError):
                    self._send_json(
                        {"error": "BAD_REQUEST",
                         "message": "version (>=0) and serial (0000..FFFF) required"},
                        400)
                    return
                body, status = _proof_response(self.store, version, serial)
                self._send_json(body, status)
            elif path == "/" or path == "/index.html":
                self._send_html(PAGE_HTML)
            else:
                self._send_json({"error": "NOT_FOUND", "message": path}, 404)
        except Exception:  # noqa: BLE001 - 服务不因单个请求崩溃
            traceback.print_exc()
            self._send_json({"error": "INTERNAL", "message": "internal error"}, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send_json({"error": "BAD_JSON", "message": "invalid JSON body"},
                            400)
            return
        try:
            if parsed.path == "/api/batches":
                expected_root = str(payload.get("expected_root", ""))
                items = payload.get("items", [])
                note = str(payload.get("note", ""))[:200]
                result = self.store.apply_batch(expected_root, items, note)
                self._send_json(result, 201)
            elif parsed.path == "/api/verify":
                # 独立复算入口：调用方提交证明，按同样规则重算根。
                proof = _proof_from_payload(payload)
                recomputed, valid = verify_proof(proof)
                self._send_json({
                    "recomputed_root": recomputed.hex(),
                    "expected_root": proof.root.hex(),
                    "root_check_ok": valid,
                }, 200 if valid else 422)
            else:
                self._send_json({"error": "NOT_FOUND",
                                 "message": parsed.path}, 404)
        except BatchError as exc:
            self._send_json({"error": exc.code, "message": str(exc)}, 400)
        except StaleRootError as exc:
            self._send_json({"error": "STALE_ROOT", "message": str(exc)}, 409)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self._send_json({"error": "INTERNAL", "message": "internal error"}, 500)


def _proof_from_payload(payload: dict):
    """从 JSON 重建 Proof（供 /api/verify 复算，可能已被篡改）。"""
    from .store import Proof

    try:
        serial = int(str(payload["serial"]), 16)
        version = int(payload["version"])
        status = (H.STATUS_REVOKED
                  if payload.get("status") == "revoked" else H.STATUS_ACTIVE)
        included = bool(payload.get("included"))
        root = H.from_hex(payload["root"])
        siblings_hex = payload["siblings"]
        if not isinstance(siblings_hex, list) or len(siblings_hex) != H.TREE_LEVELS:
            raise ValueError("need 16 siblings")
        siblings = [H.from_hex(s) for s in siblings_hex]
        path = payload.get("path_bits", H.path_bits(serial))
        if (not isinstance(path, list) or len(path) != H.TREE_LEVELS
                or any(b not in (0, 1) for b in path)):
            raise ValueError("need 16 path bits")
        leaf = H.from_hex(payload.get("leaf_digest", H.EMPTY_LEAF.hex()))
        if included and leaf == H.EMPTY_LEAF:
            leaf = H.leaf_digest(serial, H.STATUS_REVOKED)
    except (KeyError, TypeError, ValueError) as exc:
        raise BatchError("BAD_PROOF", f"invalid proof payload: {exc}") from exc
    return Proof(version, serial, status, included, root, leaf, siblings, path)


def build_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    store = Store(db_path)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    return httpd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("APP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("APP_PORT", "8000")))
    parser.add_argument("--db", default=DB_PATH)
    args = parser.parse_args()
    httpd = build_server(args.host, args.port, args.db)
    print(f"serving on http://{args.host}:{args.port} (db={args.db})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

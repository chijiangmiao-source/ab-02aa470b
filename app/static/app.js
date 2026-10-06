/* Reviewer page: versioned queries, fully local proof recomputation (SHA-256),
   sibling-tamper demonstration and optimistic batch submission. */
"use strict";

/* ----------------------------- SHA-256 (pure JS) ------------------------ */
const SHA256 = (function () {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function hash(message) {
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19,
    ]);
    const len = message.length;
    const withPad = (((len + 8) >> 6) + 1) * 64;
    const buf = new Uint8Array(withPad);
    buf.set(message);
    buf[len] = 0x80;
    const bitLenHi = Math.floor(len / 0x20000000);
    const bitLenLo = (len << 3) >>> 0;
    const dv = new DataView(buf.buffer);
    dv.setUint32(withPad - 8, bitLenHi);
    dv.setUint32(withPad - 4, bitLenLo);

    const w = new Uint32Array(64);
    for (let off = 0; off < withPad; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }
  return { hash };
})();

/* ------------------------------- tree rules ----------------------------- */
const LEAF_PREFIX = 0x52, BRANCH_PREFIX = 0x02, EMPTY_PREFIX = 0x00;
const LEVELS = 16;

function concat(...arrays) {
  const n = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(n);
  let p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}
function byte(b) { return new Uint8Array([b]); }
function leafDigest(key, status) {
  return SHA256.hash(concat(byte(LEAF_PREFIX), key, byte(status)));
}
function branchDigest(left, right) {
  return SHA256.hash(concat(byte(BRANCH_PREFIX), left, right));
}
function serialToKey(serial) {
  if (!/^[0-9A-Fa-f]{4}$/.test(serial)) throw new Error("序列号须为 4 位十六进制");
  const v = parseInt(serial, 16);
  return new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
}
function hexToBytes(hex) {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error("非法十六进制");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/* empty subtree digests, index = height */
const EMPTY = [SHA256.hash(byte(EMPTY_PREFIX))];
for (let h = 0; h < LEVELS; h++) {
  EMPTY.push(branchDigest(EMPTY[h], EMPTY[h]));
}

/* Recompute root independently from the claimed leaf (or empty slot) and the
   sibling chain. */
function recompute(serial, proof, siblings) {
  const key = serialToKey(serial);
  const status = proof.status === "revoked" ? 1 : 0;
  let current = proof.included ? leafDigest(key, status) : EMPTY[0];
  const trace = [{ mergeLevel: 0, digest: current,
                   kind: proof.included ? "leaf" : "empty_slot" }];
  const keyInt = (key[0] << 8) | key[1];
  for (let i = 0; i < LEVELS; i++) {
    const mergeLevel = i + 1;          // this merge produces a height-(i+1) node
    const bit = (keyInt >> i) & 1;     // path bit consumed at this merge
    let sib = hexToBytes(siblings[i].digest);
    current = bit === 0 ? branchDigest(current, sib) : branchDigest(sib, current);
    trace.push({ mergeLevel, bit, sibling: siblings[i].digest, digest: current });
  }
  return { computedRoot: bytesToHex(current), trace };
}

/* --------------------------------- API ----------------------------------- */
async function api(path, options) {
  const resp = await fetch(path, options);
  let body = null;
  try { body = await resp.json(); } catch (e) { /* non-json */ }
  if (!resp.ok) throw Object.assign(new Error((body && body.error) || ("HTTP " + resp.status)),
                                    { body, status: resp.status });
  return body;
}

const $ = (id) => document.getElementById(id);
let versions = [];

async function loadVersions(selectVersion) {
  const data = await api("/api/versions");
  versions = data.versions;
  const sel = $("version");
  sel.innerHTML = "";
  for (const v of versions) {
    const opt = document.createElement("option");
    opt.value = String(v.version);
    opt.textContent = "v" + v.version + (v.comment ? " — " + v.comment : "") +
                      "  [" + v.root.slice(0, 12) + "…]";
    sel.appendChild(opt);
  }
  if (selectVersion != null) sel.value = String(selectVersion);
  else sel.value = String(versions[versions.length - 1].version);
  const latest = versions[versions.length - 1];
  if (!$("expectedRoot").value) $("expectedRoot").value = latest.root;
}

/* ------------------------------- query flow ------------------------------ */
async function runQuery() {
  $("qerror").hidden = true;
  const serial = $("serial").value.trim().toUpperCase();
  const version = parseInt($("version").value, 10);
  let data;
  try {
    serialToKey(serial);
    data = await api("/api/state?version=" + version + "&serial=" + encodeURIComponent(serial));
  } catch (err) {
    $("qerror").textContent = err.message;
    $("qerror").hidden = false;
    $("result").hidden = true;
    return;
  }

  const publishedRoot = data.root;
  const siblings = data.proof.siblings.map((s) => ({ digest: s.digest }));

  /* Optional tamper: flip the last hex nibble of one sibling digest. */
  let tampered = false;
  if ($("tamper").checked) {
    const lvl = Math.max(1, Math.min(16, parseInt($("tamperLevel").value, 10) || 1));
    const idx = lvl - 1; // siblings[0] is merge level 1 (leaf -> first branch)
    const orig = siblings[idx].digest;
    const last = orig.slice(-1);
    const flipped = (parseInt(last, 16) ^ 0x1).toString(16);
    siblings[idx] = { digest: orig.slice(0, -1) + flipped };
    tampered = true;
  }

  const { computedRoot, trace } = recompute(serial, data.proof, siblings);
  const ok = computedRoot === publishedRoot;

  $("result").hidden = false;
  $("versionRoot").textContent = publishedRoot;
  $("rSerial").textContent = serial;
  const badge = $("rStatus");
  badge.textContent = data.status === "revoked" ? "已吊销 revoked (1)"
                                                 : "未吊销 not_revoked (0)";
  badge.className = "badge " + data.status;
  $("rKind").textContent = data.proof.included
    ? "（叶子包含证明 inclusion；槽位状态如上）"
    : "（空槽未包含证明 non-inclusion；该序列号从未写入，按未吊销处理）";

  const conclusion = $("conclusion");
  if (tampered) {
    conclusion.innerHTML = ok
      ? '<div class="fail">异常：篡改后仍通过？</div>'
      : '<div class="fail">如预期：兄弟摘要被篡改，本地复算根与版本根不一致 —— 根校验失败，证明被拒绝。</div>'
        + '<p class="hint">篡改后复算根：<span class="mono">' + computedRoot + "</span></p>";
  } else {
    conclusion.innerHTML = ok
      ? '<div class="pass">✓ 本地复算通过：复算根等于该版本公布根，状态结论「'
        + (data.status === "revoked" ? "已吊销" : "未吊销") + "」对版本 v" + version + " 成立。</div>"
      : '<div class="fail">✗ 根校验失败：复算根与版本根不一致，证明无效。</div>';
  }

  const tbody = $("layers");
  tbody.innerHTML = "";
  // trace[0] is the claimed leaf; rows are the 16 merge levels, leaf -> root.
  for (let i = 1; i < trace.length; i++) {
    const t = trace[i];
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td class="lvl">' + t.mergeLevel + "</td>" +
      '<td class="lvl">bit=' + t.bit + "（兄弟在" + (t.bit === 0 ? "右" : "左") + "）</td>" +
      '<td class="mono">' + t.sibling + "</td>" +
      '<td class="mono">' + t.digest + "</td>";
    tbody.appendChild(tr);
  }
  const leafRow = document.createElement("tr");
  leafRow.innerHTML =
    '<td class="lvl">0 (起点)</td><td class="lvl">—</td>' +
    '<td class="lvl">' + (trace[0].kind === "leaf" ? "叶子摘要" : "空槽摘要 EMPTY[0]") +
    "</td><td class=\"mono\">" + trace[0].digest + "</td>";
  tbody.insertBefore(leafRow, tbody.firstChild);
}

/* ------------------------------- batch flow ------------------------------ */
function parseItems(text) {
  text = text.trim();
  if (text.startsWith("[")) return JSON.parse(text);
  const items = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const parts = t.split(/[,\t]/).map((x) => x.trim());
    if (parts.length !== 2) throw new Error("无法解析行：" + line);
    let [serial, status] = parts;
    serial = serial.toUpperCase();
    serialToKey(serial);
    if (seen.has(serial)) throw new Error("批内重复序列号：" + serial);
    seen.add(serial);
    const s = status.toLowerCase();
    if (s === "revoked" || s === "1" || s === "revoke") status = "revoked";
    else if (s === "not_revoked" || s === "unrevoked" || s === "0" || s === "unrevoke")
      status = "not_revoked";
    else throw new Error("非法状态：" + status + "（行：" + line + "）");
    items.push({ serial, status });
  }
  return items;
}

async function submitBatch() {
  const out = $("sresult");
  out.className = "hint";
  try {
    const items = parseItems($("items").value);
    const body = { expected_root: $("expectedRoot").value.trim().toLowerCase(), items };
    const data = await api("/api/batches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    out.className = "pass";
    out.textContent = "✓ 已在同一持久化提交中发布版本 v" + data.version + "，新根：" + data.root;
    await loadVersions(data.version);
    $("expectedRoot").value = data.root;
  } catch (err) {
    out.className = "fail";
    let extra = "";
    if (err.body && err.body.code === "stale_root")
      extra = "（陈旧根冲突；最新根为 " + err.body.latest_root + "，版本 v" + err.body.latest_version + "，本次未生成任何版本）";
    out.textContent = "✗ 批次被拒绝：" + err.message + extra;
  }
}

/* --------------------------------- init ---------------------------------- */
$("query").addEventListener("click", runQuery);
$("submit").addEventListener("click", submitBatch);
$("fillRoot").addEventListener("click", () => {
  const latest = versions[versions.length - 1];
  if (latest) $("expectedRoot").value = latest.root;
});
$("serial").addEventListener("input", (e) => {
  e.target.value = e.target.value.replace(/[^0-9a-fA-F]/g, "").toUpperCase().slice(0, 4);
});
loadVersions().catch((err) => {
  $("qerror").textContent = "加载版本失败：" + err.message;
  $("qerror").hidden = false;
});

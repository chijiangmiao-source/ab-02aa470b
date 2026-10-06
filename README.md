# 地面设备短序列号吊销目录（版本化十六层稀疏 Merkle 树）

审查员可选择**任一已发布目录版本**，在该版本下确认某个四位十六进制短序列号
（`0000`..`FFFF`）**已吊销 / 未吊销**，并取得可独立复算的包含或未包含证明；
后续批次绝不改变旧版本的查询结果。

## 摘要与树规范

序列号为 16 比特，目录是固定 **16 层二叉稀疏 Merkle 树**，路径位自高位到低位
（0=左，1=右）。全部摘要为 SHA-256，并用前缀字节做域分离：

| 对象 | 计算规则 |
|---|---|
| 叶子 | `SHA256(0x00 ‖ serial_be(2字节) ‖ status(1字节))`，仅已吊销(status=1)物化；解除(status=0)回归空叶 |
| 分支 | `SHA256(0x01 ‖ left(32) ‖ right(32))` |
| 空叶 | `SHA256(0x02)` |

空树根：空叶成对向上 16 层得到的默认摘要（`GENESIS_ROOT`）。
节点按摘要内容寻址、不可变，因此旧版本根下的证明永久有效。

## 批次提交语义

操作员一次可提交 **1..32 项**吊销/解除，以及其看到的目录根：

- 仅当 `expected_root` 等于当前最新根（乐观并发控制）时，才在**同一个
  SQLite 持久化事务**中写入：新节点、新版本根、批次条目、以及每一项可独立
  复算的包含/未包含证明；
- 陈旧根 → `409 STALE_ROOT`，回滚，不生成版本；
- 批内重复序列号 → `400 DUPLICATE_SERIAL`，不生成版本；
- 非法状态 / 非法序列号 / 超过 32 项 → `400`，不生成版本。

## 运行（Docker Compose）

```bash
HOST_PORT=8080 docker compose up --build -d     # 宿主机端口可配置，默认 8080
# 页面:    http://localhost:8080/
# 健康:    http://localhost:8080/health
# 一次性验收（执行后退出，退出码报告结果）:
docker compose run --rm verify
echo "verify exit code: $?"
```

`verify` 服务围绕以下场景完成构建检查、代码测试与 API/HTTP 冒烟：
批次更新、**历史未包含证明**、**陈旧根冲突**、**篡改兄弟摘要后根校验失败**，
并额外对 `web` 服务做跨容器 HTTP 冒烟（`BASE_URL`）。

不使用 Docker 时也可直接运行（零三方依赖，仅需 Python 3.11+ 标准库）：

```bash
python -m app.verify                       # 全部验收（自启临时服务）
python -m app.server --db ./data/directory.db   # 启动页面/API，默认端口 8000
APP_PORT=8080 HOST_PORT=... python -m app.server  # 可用环境变量改端口
```

## HTTP API

| 方法/路径 | 说明 |
|---|---|
| `GET /health` | 健康响应：最新版本与最新根 |
| `GET /api/versions` | 全部已发布版本及最新根 |
| `GET /api/version/{v}` | 某版本根与该版本批次明细 |
| `GET /api/proof?version=v&serial=A1B2` | 指定版本下的状态、16 层兄弟摘要（高→低）、复算根与结论 |
| `POST /api/batches` | 提交批次：`{"expected_root":"<hex>","items":[{"serial":"00A1","status":"revoked"}]}`；状态取 `revoked`/`released` |
| `POST /api/verify` | 独立复算入口：提交完整证明，返回 `root_check_ok`（200/422） |

证明的独立复算规则（任何人、任何语言可重放）：

```
node = leaf_digest（未包含时为 SHA256(0x02)）
for i = 15 .. 0:           # 自下而上
    if path[i] == 0: node = SHA256(0x01 ‖ node ‖ siblings[i])
    else:            node = SHA256(0x01 ‖ siblings[i] ‖ node)
valid 当且仅当 node == 所选版本根
```

页面中的"浏览器本地复算"使用 Web Crypto 在浏览器内按同一规则重算根，
并提供"篡改第 8 层兄弟摘要"按钮，可直接观察根校验失败。

## 存储

SQLite（WAL）。表：`versions`（版本根）、`batches`/`batch_items`、
`nodes`（内容寻址不可变节点）、`proofs`（每版本每序列号证明快照）。
数据库位于卷 `directory-data`（容器内 `/data/directory.db`）。

# 四位十六进制短序列号吊销目录

地面设备入网前，审查员需要确认某个短序列号在**指定历史版本**的目录中是「已吊销」还是「未吊销」，而不只是查询当前记录。本服务用一棵固定 **16 层稀疏 Merkle 树**维护目录，每个已发布版本带一个目录根；任何版本、任何序列号的状态都附带可独立复算的包含 / 未包含证明。

## 目录结构

```
app/
  tree.py      # 摘要规则、16 层路径、Proof（独立复算/校验）
  storage.py   # SQLite 持久化、单事务乐观并发批次、证明重建
  server.py    # 标准库 http.server：JSON API + 页面 + /health
  static/      # 审查页面（纯 HTML/JS，内置 SHA-256，本地复算）
tests/         # 23 个代码测试（unittest，标准库）
scripts/
  verify.sh    # compose verify 一次性验收入口（退出码即验收结论）
  live_smoke.py# 对已部署服务的 API/HTTP 冒烟（客户端独立复算）
Dockerfile
docker-compose.yml
```

应用本身**只依赖 Python 3.11 标准库**，无需联网安装 Python 包。

## 摘要规则（与实现强绑定）

序列号为 4 位十六进制（16 位整数，大端 2 字节），路径位从**高位到低位**（MSB→LSB）取 16 位，固定 16 层二叉树：

| 元素 | 计算 |
|---|---|
| 叶子 | `SHA256( 0x52 ‖ serial_BE16 ‖ status )`，`status = 0x00` 未吊销 / `0x01` 已吊销 |
| 分支 | `SHA256( 0x02 ‖ left32 ‖ right32 )` |
| 空叶子（高度 0） | `SHA256( 0x00 )` |
| 空子树（高度 h） | `SHA256( 0x02 ‖ empty[h-1] ‖ empty[h-1] )`，空树根为 `empty[16]` |

- **包含证明**：槽位已写入，起点是叶子摘要，再沿 16 个兄弟摘要逐层合并到根。
- **未包含证明**：该序列号在该版本从未写入（空槽），起点是 `empty[0]`，兄弟链合并到根；空槽默认状态为「未吊销」。
- 解除吊销会写入 `status=0` 的叶子（槽位仍存在，属包含证明），其历史版本仍可证明曾为已吊销。

证明的兄弟链按「叶→根」打包 16 个摘要；复算时第 i 步（0 基）使用序列号的第 i 位（LSB 起），位为 0 则当前摘要在左，为 1 则在右。

## 持久化与并发

SQLite（WAL），表：`versions`（版本根，追加）、`leaf_events`（每版本叶子事实，追加）、`nodes`（内容寻址、不可变的分支节点）、`proofs`（每批次项随提交落盘的证明）。

一次批次在**单个 `BEGIN IMMEDIATE` 事务**中完成：

1. 校验 1–32 项、四位十六进制序列号、合法状态、**批内无重复序列号**（非法则拒绝，不产生版本）；
2. 持写锁重读最新根，与操作员提交的 `expected_root` 比较——不一致即 `StaleRootError`，整批回滚，不写任何节点/版本/证明（HTTP 409）；
3. 同一提交内写入新分支节点、新版本根、每项叶子事件与每项可独立复算的证明，并推进 `latest_version`。

旧版本根与数据不可变，后续批次只追加新版本，**旧版本查询结果永不改变**。

## HTTP 接口

| 方法/路径 | 说明 |
|---|---|
| `GET /health` | `{status, latest_version, latest_root}` |
| `GET /` / `GET /static/app.js` | 审查页面 |
| `GET /api/versions` | 全部已发布版本及其根 |
| `GET /api/state?version=&serial=` | 该版本根、状态、`kind=inclusion/non_inclusion`、16 层兄弟摘要、复算轨迹 |
| `POST /api/batches` | 提交批次：`{"expected_root": "<hex>", "items":[{"serial":"0A3F","status":"revoked"}], "comment":""}` |

`status` 接受 `0/1`、`revoked`、`not_revoked`（别名 `unrevoked`）。成功返回 `201 {version, root}`；陈旧根返回 `409 {code:"stale_root", latest_version, latest_root}`；非法批次返回 `400 {code:"invalid_batch"}`。

## 页面

选择任一已发布版本 + 输入序列号后显示：该版本根、状态徽章、证明类型、16 层逐层兄弟摘要与逐层复算摘要，以及**浏览器本地 SHA-256 复算结论**（不依赖服务端返回的 `computed_root`）。勾选「篡改测试」并指定层（1=叶侧 … 16=根侧），可翻转该层兄弟摘要末位后复算，页面将显示**根校验失败**。页面也可直接提交批次（期望根默认填入最新根）。

## 运行（Docker Compose）

```bash
docker compose up web --build          # 默认宿主机端口 8080
HOST_PORT=9090 docker compose up web   # 可配置宿主机端口
curl http://localhost:8080/health
```

一次性验收服务（构建检查 + 代码测试 + 对运行中 web 的 API/HTTP 冒烟，退出码即结论）：

```bash
docker compose run --rm verify
# 成功末尾打印 ALL ACCEPTANCE STAGES PASSED，退出码 0；任一阶段失败退出码 1
```

verify 覆盖：批次更新（含本地独立复算根/证明）、历史版本未包含证明、陈旧根冲突（409 且无新版本）、16 个兄弟位置逐个篡改后根校验失败，以及非法批次数项 400。

## 本地无 Docker 时

```bash
python3 -m unittest discover -s tests -v          # 代码测试
python3 -m compileall -q app tests                # 构建检查
DB_PATH=/tmp/dir.db PORT=8080 python3 -m app.server
BASE_URL=http://127.0.0.1:8080 python3 scripts/live_smoke.py
```

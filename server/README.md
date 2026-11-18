# 自建遥测后端（与客户端协议兼容）

Canta 客户的 `util/Telemetry.kt` 只认四个 RPC，所以换后端只需要改两个常量：

```
BASE_URL        = https://<PROJECT>.supabase.co/rest/v1/rpc/
PUBLISHABLE_KEY = <supabase publishable / anon key>
```

| RPC | 请求 | 返回 |
|---|---|---|
| `challenge` | `{}` | `{challenge, sig}`，一次性、10 分钟内有效 |
| `record` | `{payload, challenge, sig, x}` | `{ok, accepted}` |
| `package_scores` | `{}` | 每个包的全局聚合 |
| `package_scores_for` | `{p_rom, p_rom_version}` | 指定 ROM（`-1` = 整个家族）的聚合 |

Proof of Work 与客户端 `util/Pow.kt` 完全一致：

```
prefix = challenge + ":" + hex(sha256(payload)) + ":" + x
通过条件：sha256(prefix) 前 8 字节大端 < floor(2^64 / (10000 * 事件数))
```

## 部署

```bash
# 1. 建 Supabase 项目，拿 project-ref 和 anon key
supabase link --project-ref PROJECT_REF
supabase db push          # 应用 supabase/migrations/*.sql

# 2. 定时清理原始事件（保留 35 天，只留聚合）
select cron.schedule('purge-telemetry', '30 3 * * *', $$select public.purge_raw_events()$$);

# 3. 客户端指向新后端：composeApp/.../util/TelemetryConfig.kt
```

## 本地验证（真 PostgreSQL，WASM 版）

```bash
cd server
npm install
npm test
```

`test/protocol.test.mjs` 用 PGlite 起一个真 Postgres，跑完两个迁移后验证：

- 正常批次写入；同一 challenge 重放被拒；
- 篡改 payload → PoW 校验失败；非法事件类型 → 拒绝；
- 五种 verdict：`SAFE` / `BOOTLOOP`（救援或大量装回）/ `BREAKS` / `UNCLEAR` / `INSUFFICIENT`；
- ROM 版本级、家族级（`-1`）、未知 ROM（0 行）三种查询；
- `purge_raw_events()` 清空原始事件。

## 判分阈值（本项目自己定的，上游没公开）

```
uninstalls < 5                 -> INSUFFICIENT
restored / uninstalls >= 15%   -> BOOTLOOP   （被手动救回过，最强信号）
(reinstalled+restored)/uninstalls >= 30% -> BOOTLOOP
(reinstalled+restored)/uninstalls >= 10% -> BREAKS
survived >= 50% 且上面 <= 2%   -> SAFE
其余                            -> UNCLEAR
```

`restored` 是本 fork 新增的事件：包在 build 未变的情况下又被装回来，只可能是人手动装回去的，
所以它单独计入判分，也是「这批卸载救过砖」的唯一数据来源。

## 隐私

- 只存 brand / ROM 家族 / ROM 主版本 / SDK，不存机型、build 号、指纹、安装 ID；
- 原始事件按 `purge_raw_events()` 过期丢弃，只留聚合；
- 表上开了 RLS 且没有任何 policy：只有 RPC 能被 anon 调，直接读表拿不到东西。

## 部署到你自己的 Supabase（一步）

1. 控制台 → **SQL 编辑器** → 粘贴执行 [apply-all.sql](supabase/apply-all.sql)（等价于依次跑两个迁移文件）；
2. 建一个定时任务清理原始事件（35 天），例如 pg_cron：

```sql
select cron.schedule('purge-telemetry', '30 3 * * *', $$select public.purge_raw_events()$$);
```

3. App 端已默认指向本项目：`TelemetryEndpoints.BASE_URL = https://axuhfogeovtsbxokqccf.supabase.co/rest/v1/rpc/`、
   `API_KEY = sb_publishable_YipHHrFaw1E2q5qTUVPl0A_plD7Q5yS`（可用 `-Pcanta.telemetry.baseUrl/.apiKey` 覆盖）。

执行完可以自测（在能连上 supabase.co 的机器上）：

```bash
KEY=sb_publishable_YipHHrFaw1E2q5qTUVPl0A_plD7Q5yS
curl -s -H "apikey: $KEY" -H "Content-Type: application/json" -d '{}' \
  https://axuhfogeovtsbxokqccf.supabase.co/rest/v1/rpc/package_scores
# 无数据时返回 []；表没建好时返回 500/PostgREST error，一眼能看出来
```

App 端的自测：打开「分享匿名卸载数据」后卸载一个包、重启、再开 App，
日志 `Telemetry` 会打 `Sent N telemetry events`；`package_scores` 会多出该包的行，
`verdict` 初始为 `INSUFFICIENT`，数据攒够后才会变。

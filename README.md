# x-anycast-sub

给 **X 及其所属域名**做的 AdGuard Home 订阅：把受影响域名的 A 记录钉到一条**能完成 TLS 握手**的 anycast 边缘地址上（借一条能走通的路径），同时让它们的 AAAA 返回 `NXDOMAIN`，逼客户端走 IPv4。

项目分两份订阅，对应两类主机：

- **`xcom.txt`** —— 托管在 Cloudflare 的主机，借 Cloudflare 边缘 IP 完成握手。
- **`xcom-media.txt`** —— 托管在 Fastly 的图片与媒体域名，Fastly 的地址同样按可达性单独优选。

两边的思路一致：都走 anycast 边缘，都是「换一条能握手的路径」。区别只在地址从哪来，所以名字取 anycast，不限定在 Cloudflare。规则由 GitHub Actions 定时复验后发布到 GitHub Pages。

`xcom.txt` 覆盖 `x.com` 及其子域、`twitter.com` 与它的 `www`、`mobile` 和业务子域（`api`、`upload`、`syndication`、`help`、`analytics`、`business`、`developer`、`investor`）、`t.co` 短链。

> **前提：本订阅只解决 DNS 层。**
> 它不提供 TLS 分片、伪装或抗干扰能力。如果你的线路对该主机的 SNI 做了阻断，客户端必须**自备支持 TLS 分片、异步干扰等功能的工具**（technique、zapret 等），否则仍然连不上。

## 订阅地址

```
https://PlumCraneCwC.github.io/x-anycast-sub/xcom.txt
https://PlumCraneCwC.github.io/x-anycast-sub/xcom-media.txt
```

第一条是 Cloudflare 主机，第二条是 Fastly 媒体主机，**两条都要加**。全部加在 AdGuard Home 的「过滤器 → DNS 阻止列表」里。另外注意两个设置：

- **更新间隔**建议改成 1 小时（默认 24 小时，规则会滞后）
- 本订阅只改写解析结果（A 指向借来的边缘、AAAA 返回 `NXDOMAIN`），不含 block 动作，不会拦截 HTTP 流量

## 它做什么

对 `targets.txt` 里的每个条目，输出两条规则：

```
||x.com^$dnstype=A,dnsrewrite=NOERROR;A;<边缘地址>
||x.com^$dnstype=AAAA,dnsrewrite=NXDOMAIN
```

- **A 重写**：把域名指向一条当前可与之完成 TLS 1.3 握手的边缘地址
- **AAAA 屏蔽**：返回 `NXDOMAIN`

**未列出的域名一律不改写。**

## 用了之后会怎样

前提是客户端已经具备 TLS 分片能力（见开头）。满足这一点时：

- X 的网页和 App 能正常打开，不再卡在 `403` 或 reload 页
- 时间线里的图片、视频从 `xcom-media.txt` 那条路径加载
- **其它域名不受影响**：规则按域名精确匹配，既不按 IP 段拦，也不含任何 block 动作

不满足前提时，DNS 这一层已经做对了，但 SNI 仍会在线路侧被切断——这时候问题不在订阅。

## 条目与通配

`targets.txt` 支持两种写法：

- `||x.com^` —— 通配，A 重写覆盖 `x.com` 及所有子域，新子域自动生效
- `api.x.com` —— 精确主机

但 **AAAA 的通配 `dnsrewrite` 不作用于子域**，所以像 `api.x.com` 这种被 App 单独使用的主机必须再显式列一遍，否则它的 AAAA 不会被屏蔽。

`twitter.com` 故意不用通配：`platform.twitter.com` 等媒体主机托管在 Fastly 上，通配改写会把它们一并指到 Cloudflare，握手会因证书不匹配失败。

## 地址是从哪来的

每个主机按优先级取地址：

1. `static-ips.txt` 里为该主机显式写的固定地址
2. 社区维护的客户端优选域名解析出的 Cloudflare 边缘（由定期任务刷新）
3. GitHub runner 上 `jsdelivr.com` 的 A 记录

选定后仍会在 runner 上复验（不带 `--trust-static-pins` 时）：直连 TCP/443、校验证书与 SNI 是否匹配、发送同名 `Host` 的 HTTP/1.1 请求；每地址测 3 次、至少 2 次通过才算数。全部候选失败则工作流失败、保留上一版，不会发布未经验证的规则。

自动化发布带 `--trust-static-pins`，直接采用 `static-ips.txt` 里的地址、跳过这轮复验：同一地址在几秒内连打几十次握手会触发边缘限速，复验反而会把一条本来可用的地址测死。

## Fastly 媒体主机

`xcom-media.txt` 处理另外一类主机：`pbs.twimg.com`、`abs.twimg.com`、`video.twimg.com`、`ton.twimg.com`、`cdn.syndication.twimg.com`。
它们 CNAME 到 `*.map.fastly.net`，不在 Cloudflare 上，借 CF 边缘没有用——Fastly 的真实地址集合里混着一批握手永远完不成的地址。

所以用 `scripts/probe_media.py` 走另一套逻辑：在 Fastly 的公开段里取样，加上这些域名当前解析出的地址，逐个做 TLS 1.3 握手，留下能握手的、每个主机取最快的一条写进 `xcom-media.txt`。

工作流 `.github/workflows/media.yml` 每 30 分钟跑一次（Fastly 边缘失效得比 Cloudflare 频繁），有变化就提交并重新发布 Pages。它跑在 GitHub 的 runner 上，只能筛掉「边缘本身死了、证书不匹配」这类问题；国内线路自己的 SNI 阻断它看不出来。

所以拆成两段：

1. 国内侧的探测任务每 30 分钟实测一遍，把真正能握手的地址写进 `media-ips.txt` 并提交（每行 `主机名 地址`）。
2. `media.yml` 用 `--ips media-ips.txt` 读这份清单：**上报的地址优先生效**，只有上报的主机全失败时才退回 runner 自己的猜测（解析地址 + 已知边缘 + Fastly 段取样）。

两边都以 TLS 1.3 握手为准，任何合法 HTTP 状态行都算通过——Fastly 对 `/` 返回 400 是正常的。

明确**不**处理的主机：`abs-0.twimg.com`、`pbs-0.twimg.com`、`r.twimg.com`、`ma.twimg.com`、`g.twimg.com`、`twttr.com`、`tweetdeck.com`。它们在 Twitter 自有的 AS13414 里，整个自治域被封，改 DNS 没有意义。

## Cloudflare 入口怎么选

参考 [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip) 的思路：不盯着几个手挑的入口，而是把 Cloudflare 公布的 IPv4 段整体抽样。

1. 每天拉一次 `https://www.cloudflare.com/ips-v4`；每段随机取 5 个 /24、再随机化最后一段，约 75 个候选，另补几个历史可用入口。
2. 16 路并发，对每个候选发一次 `x.com` 的 TLS 握手加 HTTP 请求，4 秒超时，任何 2xx/3xx/4xx 都算通过。
3. 取最快的一个写进 `static-ips.txt`。

`x.com` 通就够——同一个 zone 在 Cloudflare 边缘上共用证书，一个入口能完成握手，`api.x.com`、`t.co` 这些同 zone 主机通常也能用，所以不必逐个主机复测。

## `static-ips.txt`

`static-ips.txt` 存放「主机名 + 一条能完成握手的固定地址」，每行 `主机名 地址`，给这些主机固定一个已验证的边缘地址。

```
api.x.com <边缘地址>
t.co <边缘地址>
```

写入该文件的条目跳过候选搜索。CI 发布时带 `--trust-static-pins`，直接采用这里的地址、不再逐条探测（原因见上一节）；本地不带该参数时才会复验，收到任何合法 HTTP 状态行即算通过，边缘对 `/` 返回 400/403 属正常。

`static-ips.txt` 由优选任务重新生成并提交（当前为手动触发），**手工修改会被下一次运行覆盖**。

## 发布

1. 仓库默认分支 `main`
2. Settings → Pages → Source 选 **GitHub Actions**
3. Actions → `Refresh and publish affected X AdGuard rules` → Run workflow
4. 首次部署完成后订阅地址为 `https://<OWNER>.github.io/<REPO>/xcom.txt`

`xcom.txt` 的工作流每 3 小时跑一次（cron `23 */3 * * *`，UTC），GitHub 高负载时可能延迟，`targets.txt` / `static-ips.txt` / `scripts/` / `site/` 变更也会触发。`xcom-media.txt` 由另一个每 30 分钟的工作流刷新。

## 回滚

在 AdGuard Home 里停用或删除该订阅并刷新缓存即可。想停止自动更新可在 GitHub 停用 workflow；已部署的规则不会自动清除。想连订阅本身一起撤掉，直接删除这个仓库即可，Pages 会随之失效。

## 常见问题

**为什么不试试 IPv6？**

没验证过，原本也不打算测。两条原因随便拎一条出来都够了：

- **线路**：v4 上能挑的入口多，这条不行还能换一条；Cloudflare 公布的 v6 段只有六个 `/32`，可换的余地小得多。
- **限速**：部分运营商对 v6 流量单独限速。

就算 v6 能通，它也没有 v4 那样的回旋余地——入口被标记了换不了，路绕远了也绕不回来。所以 AAAA 直接返 `NXDOMAIN`，把客户端赶到 v4。

**为什么 AAAA 返 `NXDOMAIN`，而不是给一个假地址？**

返回一个不存在的 v6 地址，客户端会先去尝试、等超时才回落 IPv4，App 启动就慢一拍；`NXDOMAIN` 让它当场放弃 v6。

**为什么不干脆用代理或 VPN？**

> 因为这本来就是我闲来无聊折腾着玩的一个 **玩具项目**，没打算跟正经工具比。
>
> 它只做 DNS 这一层，剩下的交给客户端自己。

**订阅加上了，X 还是打不开？**

说明线路上是在 SNI 层阻断，DNS 已经没得改。检查客户端那边是否真的开了分片工具（technique、zapret 等）——没开的话换什么地址都没用。

## 本地验证

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_filter.py --output /tmp/xcom.txt --trust-static-pins
```

第二条命令会进行真实出站 DNS/TLS/HTTP 探测，只写指定输出文件。它带 `--trust-static-pins`，所以只复验 `static-ips.txt` 之外的候选；同一地址短时间内连打几十次握手会触发边缘限速，本地调试建议加 `--only` 只测少数主机。

## 目录

- `targets.txt` —— 要处理的 X 域名（通配或精确主机）
- `static-ips.txt` —— 固定地址（由定期任务刷新）
- `media-hosts.txt` —— Fastly 媒体主机清单
- `media-ips.txt` —— 国内实测可用的 Fastly 地址
- `scripts/build_filter.py` —— 探测候选地址并生成 `xcom.txt`
- `scripts/probe_media.py` —— 探测 Fastly 边缘并生成 `xcom-media.txt`
- `scripts/diagnose_hosts.py` —— 客户端侧诊断：哪些主机当前握手失败

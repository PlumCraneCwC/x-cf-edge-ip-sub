# x-cf-edge-ip-sub

给 **x.com 及其子域**做的 AdGuard Home 订阅：把受影响的域名 A 记录钉到一条**能完成 TLS 握手**的 Cloudflare 边缘地址上，同时让它们的 AAAA 返回 `NXDOMAIN`，逼客户端走 IPv4。规则由 GitHub Actions 每 3 小时复验一次后发布到 GitHub Pages。

项目主体是**借 Cloudflare 边缘 IP**。少数不在 Cloudflare 上的主机（X 的 Fastly 媒体域名）属于特例，单独写在 [Fastly 特例](#fastly-特例) 一节。

> **前提：本订阅只解决 DNS 层。**
> 它不提供 TLS 分片、伪装或抗干扰能力。如果你的线路对该主机的 SNI 做了阻断，客户端必须**自备支持 TLS 分片、异步干扰等功能的工具**（technique、zapret 等），否则仍然连不上。

## 订阅地址

```
https://PlumCraneCwC.github.io/x-cf-edge-ip-sub/xcom.txt
```

在 AdGuard Home 的「过滤器 → DNS 阻止列表」里添加即可。注意两个设置：

- **更新间隔**建议改成 1 小时（默认可能是 24 小时，规则会滞后）
- 本订阅只改 A/AAAA，不含 block 动作，不会拦截任何流量

## 它做什么

对 `targets.txt` 里的每个条目，输出两条规则：

```
||x.com^$dnstype=A,dnsrewrite=NOERROR;A;104.21.8.91
||x.com^$dnstype=AAAA,dnsrewrite=NXDOMAIN
```

- **A 重写**：把域名指向一条当前可与之完成 TLS 1.3 握手的边缘地址
- **AAAA 屏蔽**：返回 `NXDOMAIN`

未列出的域名一律不改写。

## 条目与通配

`targets.txt` 支持两种写法：

- `||x.com^` —— 通配，覆盖 `x.com` 及所有子域（新子域自动生效，**只对 A 生效**）
- `api.x.com` —— 精确主机

AdGuard Home 的**通配 `dnsrewrite` 不作用于子域**，所以像 `api.x.com` 这种被 App 单独使用的主机必须再显式列一遍，否则它的 AAAA 不会被屏蔽。

## 地址是从哪来的

每个主机按优先级取地址：

1. `static-ips.txt` 里为该主机显式写的固定地址
2. 客户端侧优选域名解析出的 Cloudflare 边缘（路由器 cron 刷新）
3. GitHub runner 上 `jsdelivr.com` 的 A 记录

选定后仍会在 runner 上复验：直连 TCP/443、验证 TLS 1.3 证书与 SNI、发送同名 `Host` 的 HTTP/1.1 请求；每地址测 3 次、至少 2 次通过才算数。全部候选失败则工作流失败、保留上一版，不会发布未经验证的规则。

## `static-ips.txt`

`static-ips.txt` 存放「主机名 + 一条能完成握手的固定地址」，每行 `主机名 地址`。它有两个用途：给部分主机固定一个已验证的边缘地址，以及承载 Fastly 特例（见下节）。

```
api.x.com 104.21.8.91
pbs.twimg.com 140.248.144.159
```

写入该文件的条目跳过候选搜索，直接探测固定地址（收到任何合法 HTTP 状态行即算通过；Fastly 对 `/` 本来就返回 400）。探测失败则整轮失败，不会发布指向黑洞的规则。

`static-ips.txt` 由路由器上的 cron 脚本每 6 小时重新生成并提交，手工修改会被下一轮覆盖。

## Fastly 特例

X 的媒体域名（`pbs.twimg.com`、`abs.twimg.com`、`video.twimg.com`）**不在 Cloudflare 上**，而在 Fastly 上。借 `jsdelivr.com` 的 Cloudflare IP 对它们无效——Cloudflare 边缘会对未托管的 SNI 直接返回 400，只能完成握手、拿不到内容。

对这些主机：

- 真实 A 记录里含 `146.75.44.x` 这类**TLS 黑洞**地址，客户端抽到就卡住
- 必须钉到一条在其 SNI 上能正常完成握手的 Fastly 边缘（例如 `140.248.144.159`）
- 边缘地址会变化，所以由路由器 cron 脚本定期扫描一组候选取最快可用的，写入 `static-ips.txt`

这部分不是本项目的核心手法，只是为了让 X 的图片能加载而做的补丁。

## 发布

1. 仓库默认分支 `main`
2. Settings → Pages → Source 选 **GitHub Actions**
3. Actions → `Refresh and publish affected X AdGuard rules` → Run workflow
4. 首次部署完成后订阅地址为 `https://<OWNER>.github.io/<REPO>/xcom.txt`

工作流每 3 小时自动跑一次（UTC `23` 分；GitHub 高负载时可能延迟），`targets.txt` / `static-ips.txt` / `scripts/` 变更也会触发。

## 回滚

在 AdGuard Home 里停用或删除该订阅并刷新缓存即可。想停止自动更新可在 GitHub 停用 workflow；已部署的规则不会自动清除。

## 本地验证

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_filter.py --output /tmp/xcom.txt
```

第二条命令会进行真实出站 DNS/TLS/HTTP 探测，只写指定输出文件。

## 目录

```
targets.txt          要处理的域名（通配或精确主机）
static-ips.txt       固定地址（由路由器 cron 刷新）
scripts/build_filter.py    探测候选地址并生成订阅
scripts/diagnose_hosts.py  客户端侧诊断：哪些主机当前握手失败
preferred-ip.txt     可选的优先地址列表
```

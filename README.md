# x-cf-edge-ip-sub

给 **x.com 及其子域**做的 AdGuard Home 订阅：把受影响的域名 A 记录钉到一条**能完成 TLS 握手**的 Cloudflare 边缘地址上，同时让它们的 AAAA 返回 `NXDOMAIN`，逼客户端走 IPv4。规则由 GitHub Actions 每 3 小时复验一次后发布到 GitHub Pages。

订阅里的主机都托管在 Cloudflare 上，所以都能借 Cloudflare 边缘 IP 完成握手：`x.com` 及子域、`twitter.com` 与其业务子域（`api`、`upload`、`syndication`、`help`、`analytics`、`business`、`developer`、`investor`）、`t.co` 短链。

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
||x.com^$dnstype=A,dnsrewrite=NOERROR;A;104.16.92.44
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

`twitter.com` 故意不用通配：`platform.twitter.com` 等媒体主机托管在 Fastly 上，通配改写会把它们也指到 Cloudflare，而那里不持有它们的证书。

## 地址是从哪来的

每个主机按优先级取地址：

1. `static-ips.txt` 里为该主机显式写的固定地址
2. 客户端侧优选域名解析出的 Cloudflare 边缘（路由器 cron 刷新）
3. GitHub runner 上 `jsdelivr.com` 的 A 记录

选定后仍会在 runner 上复验：直连 TCP/443、验证 TLS 1.3 证书与 SNI、发送同名 `Host` 的 HTTP/1.1 请求；每地址测 3 次、至少 2 次通过才算数。全部候选失败则工作流失败、保留上一版，不会发布未经验证的规则。

自动化发布用 `--trust-static-pins` 直接采用 `static-ips.txt` 里的地址、跳过这轮复验：同一地址在几秒内连打几十次握手会触发边缘限速，本地实测反而会把一条本来可用的地址测死。

## `static-ips.txt`

`static-ips.txt` 存放「主机名 + 一条能完成握手的固定地址」，每行 `主机名 地址`，给这些主机固定一个已验证的边缘地址。

```
api.x.com 104.16.92.44
t.co 104.16.92.44
```

写入该文件的条目跳过候选搜索，直接探测固定地址（收到任何合法 HTTP 状态行即算通过；边缘对 `/` 返回 400/403 属正常）。探测失败则整轮失败，不会发布指向黑洞的规则。

`static-ips.txt` 由路由器上的 cron 脚本每 6 小时重新生成并提交，手工修改会被下一轮覆盖。

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
python3 scripts/build_filter.py --output /tmp/xcom.txt --trust-static-pins
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

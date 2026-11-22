# x.com AdGuard Home 规则订阅（GitHub Actions + Pages）

这个小项目为**确认受影响的主机名**生成 AdGuard Home 规则。GitHub Actions 对 `targets.txt` 列出的条目逐条验证，并发布每条 A 重写及其对应的 AAAA 屏蔽。未列出的主机一律不会被改写。

支持两种条目：

- `||x.com^` —— 通配，匹配 `x.com` 及其所有子域（未来新增的子域也覆盖）
- `api.x.com` —— 精确主机

> **重要前提：本订阅只解决 DNS 层。** 它把 A 记录指向可完成 TLS 握手的 IP，并让 AAAA 返回 NXDOMAIN 迫使客户端走 IPv4，但**不提供 TLS 分片、伪装或抗干扰能力**。如果你的线路对该主机的 SNI 做了阻断，客户端必须**自备支持 TLS 分片、异步干扰等功能的工具**（如 RethinkDNS、zapret 等），否则仍然连不上。仅使用本订阅、不开任何分片工具时，被阻断的主机无法仅靠改 DNS 恢复。

## 先确认哪些主机受影响

**不要把“自动判断客户端是否被封锁”交给 GitHub runner。** GitHub runner 的网络、DNS 和客户端所在运营商路径不同；它无法可靠判断你的客户端到某个 X 子域名的原始 TLS 握手是否成功。

1. 从浏览器网络面板/连接日志收集加载 X 时实际访问的**主机名**，不要把整条 URL、Cookie、请求头等隐私内容放入仓库。
2. 在发生故障的同一台客户端、同一网络和适用的解析路径上，用下面的辅助脚本测试这些主机的当前 A/AAAA 地址的 TLS 证书握手：

   ```sh
   python3 scripts/diagnose_hosts.py --input observed-hosts.txt
   ```

   `OK` 的主机不加入规则；`AFFECTED` 表示当前解析到的所有地址连续 3 次都未完成已验证的 TLS 握手；`PARTIAL` 表示部分地址可握手、部分不行，先人工复核，脚本不会自动纳入；`UNKNOWN`（例如 DNS 无答案）不应据此判定为受影响。脚本只进行 DNS/TLS 测试，不会改配置。若浏览器使用与系统不同的 DoH/代理路径，请以实际连接记录为准。
3. 把经客户端验证为 `AFFECTED` 的条目写入 `targets.txt`。需要覆盖整族子域时用 `||域名^` 通配；ADG 的通配 `dnsrewrite` 对子域不生效，所以像 `api.x.com` 这种被 App 单独使用的主机要**再显式列一遍**，它的 AAAA 屏蔽才会生效。

可选地，脚本把 AFFECTED 主机写到单独文件供人工审核：

```sh
python3 scripts/diagnose_hosts.py --input observed-hosts.txt --write-affected work/affected-hosts.txt
```

请人工审核结果后再更新 `targets.txt` 并推送。

## 候选地址与规则

- 每个目标按以下优先级取地址：
  1. `static-ips.txt` 里为该主机显式写的固定地址（最高优先，构建时仍会复验）
  2. 客户端侧优选域名解析出的 Cloudflare 边缘（由路由器 cron 脚本刷新，见下）
  3. GitHub runner 上系统解析器返回的 `jsdelivr.com` A 记录
- 对每个候选地址：直连 TCP/443，验证 TLS 1.3 证书且 SNI 为该目标主机，再发送 `Host` 同名的 HTTP/1.1 请求。
- 每个候选地址测 3 次，至少成功 2 次才可选；成功次数优先，同次数时选成功探测延迟中位数较低者。
- 订阅对每条目标输出**两条**规则：A 重写 + AAAA `NXDOMAIN`。后者用于阻止客户端优先使用被重置的真实 IPv6 路径。

每条目标的规则形如：

```
||x.com^$dnstype=A,dnsrewrite=NOERROR;A;<已验证的IPv4>
||x.com^$dnstype=AAAA,dnsrewrite=NXDOMAIN
|api.x.com|$dnstype=A,dnsrewrite=NOERROR;A;<已验证的IPv4>
|api.x.com|$dnstype=AAAA,dnsrewrite=NXDOMAIN
```

候选地址的连通性验证发生在 GitHub runner 和刷新 `static-ips.txt` 的客户端侧脚本，所以它验证的是“该 IP 在该位置能否以该主机名握手”，不是所有客户端路径可用性的保证。此订阅应视为可撤销的实验性规则，部署后仍要从实际客户端验证。

## 固定地址：`static-ips.txt`

有些受影响主机不在 Cloudflare 边缘上（例如 `pbs.twimg.com` 走 Fastly），借 `jsdelivr.com` IP 的办法对它们无效；还有些主机的候选 IP 在特定线路上不稳定的。把这类主机和一条**在该 SNI 上仍能完成 TLS 握手**的地址写进 `static-ips.txt`，每行 `主机名 地址`：

```
pbs.twimg.com 140.248.144.159
```

这类主机在构建时跳过候选搜索，直接用固定地址探测（收到任何合法 HTTP 状态行即算通过，因为 Fastly 对 `/` 本来就返回 400）；一旦该地址探测失败，整个工作流会失败并保留上一版，不会发布会黑洞的规则。

`static-ips.txt` 由路由器上的 cron 脚本周期性重新生成并提交（每 6 小时：探测一组 Fastly 边缘和 Cloudflare 入口，取对全部 X 主机都可用且总延迟最低的地址）。手工改这个文件会被下一轮刷新覆盖，需要持久化的条目请同时改生成脚本。

## 发布步骤

1. 将本目录内容放到 GitHub 仓库默认分支 `main`（其他分支需调整 `.github/workflows/publish.yml`）。
2. 在仓库 **Settings → Pages** 中把 Source 设为 **GitHub Actions**。
3. 在 **Actions → Refresh and publish affected X AdGuard rules** 手动运行一次。以后工作流每 3 小时运行一次（UTC 的 `23` 分；GitHub 高负载时可能延迟）。
4. 首次成功部署后，订阅地址为：

   `https://<OWNER>.github.io/<REPOSITORY>/xcom.txt`

   若仓库名为 `<OWNER>.github.io`，则省略 `/<REPOSITORY>`。
5. 在 AdGuard Home 新增该过滤器订阅，不覆盖已有订阅或 DNS 设置。注意列表的**自动更新间隔**默认可能是 24 小时，建议在「过滤器 → 列表 → 更新间隔」里改成 1 小时，否则规则更新会滞后。
6. 刷新后分别查询 A 和 AAAA，确认只有已列出的条目被改写、AAAA 返回 NXDOMAIN。

## 回滚

在 AdGuard Home 停用或删除这条新订阅并刷新过滤器/缓存。若只想停止自动更新，可在 GitHub 停用该 workflow；已有部署不会自动清除。

## 本地验证

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_filter.py --output /tmp/xcom.txt
```

第二条命令会进行真实出站 DNS/TLS/HTTP 探测，只写入指定输出文件。

# AdguaedHome GFWList

基于[gfwlist](https://github.com/gfwlist/gfwlist)生成的AdguardHome分流文件  

host.conf文件需要靠openwrt防火墙规则  

```sh
#OpenWrt配置
# 针对IPv4 TCP DNS 丢弃 RST包
iptables -t raw -I PREROUTING -i pppoe-wan -p tcp --sport 53 --tcp-flags RST RST -j DROP
# 针对IPv6 TCP DNS 丢弃 RST包
ip6tables -t mangle -I PREROUTING -i pppoe-wan -p tcp --sport 53 --tcp-flags RST RST -j DROP

# 针对 IPv4 TCP FIN DNS(快速释放)
iptables -I FORWARD -o pppoe-wan -p tcp --dport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
iptables -I FORWARD -o pppoe-wan -p tcp --sport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
iptables -I FORWARD -i pppoe-wan -p tcp --dport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
iptables -I FORWARD -i pppoe-wan -p tcp --sport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
# 针对 IPv6 TCP FIN DNS(快速释放)
ip6tables -I FORWARD -o pppoe-wan -p tcp --dport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
ip6tables -I FORWARD -o pppoe-wan -p tcp --sport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
ip6tables -I FORWARD -i pppoe-wan -p tcp --dport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
ip6tables -I FORWARD -i pppoe-wan -p tcp --sport 53 --tcp-flags FIN FIN -j REJECT --reject-with tcp-reset
```

nft版本如下：
```sh
#!/bin/sh
nft delete chain inet fw4 custom_mangle_prerouting 2>/dev/null
nft delete chain inet fw4 custom_forward 2>/dev/null

nft add chain inet fw4 custom_raw_prerouting { type filter hook prerouting priority -450\; policy accept\; }
nft add chain inet fw4 custom_forward { type filter hook forward priority -350\; policy accept\; }

nft add set inet fw4 rst_drop_ports { type inet_service\; elements = { 53, 443, 853 } \; }

nft add rule inet fw4 custom_raw_prerouting iif "pppoe-wan" ip protocol tcp tcp sport @rst_drop_ports tcp flags rst counter drop
nft add rule inet fw4 custom_raw_prerouting iif "pppoe-wan" ip6 nexthdr tcp tcp sport @rst_drop_ports tcp flags rst counter drop

nft add rule inet fw4 custom_forward oif "pppoe-wan" tcp sport 53 tcp flags fin counter ct mark set 0x1 reject with tcp reset
nft add rule inet fw4 custom_forward oif "pppoe-wan" tcp dport 53 tcp flags fin counter ct mark set 0x1 reject with tcp reset
nft add rule inet fw4 custom_forward iif "pppoe-wan" tcp sport 53 tcp flags fin counter ct mark set 0x1 reject with tcp reset
nft add rule inet fw4 custom_forward iif "pppoe-wan" tcp dport 53 tcp flags fin counter ct mark set 0x1 reject with tcp reset

nft add rule inet fw4 custom_forward ct mark 0x1 tcp dport 53 counter reject with tcp reset
nft add rule inet fw4 custom_forward ct mark 0x1 tcp sport 53 counter reject with tcp reset
```
个人推荐用nft(条件支持的情况下)
因为快速释放TCP DNS 比ipt快

host2.conf无需依赖防火墙规则

data目录下的是分类  
cloudflare是SOA和NS记录包含cloudflare的  
nocloudflare是SOA和NS记录不包含cloudflare的
可以使用[domain-list-community](https://github.com/v2ray/domain-list-community)转换为.dat文件

不过分类的代码就是一坨屎山  
关于更新  
更新不定期  
推荐自己clone下来自己生成  
关于提交域名  
请直接提交到[gfwlist](https://github.com/gfwlist/gfwlist)而不是这里  
如果非要提交  
要求ISS格式  
```md
域名:example.com
是CF:是/否
可TCPING 443:是/否
```
PR格式  
```json
[
    {
        "domain":"domain:example.com",
        "isCF":true/false,
        "pingable":true/false
    }
]
```
然后合并到list.json  
方便后期代码处理~~虽然我还没写~~

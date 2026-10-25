#!/bin/bash
# node2sub 隧道地址监视：隧道 URL 一变就更新域名解析，域名本身永久不变。
# 由 systemd timer 每 2 分钟跑一次（timer 在配好 dns_config 后再启用）。
# 配置文件 ~/node2sub/dns_config（不存在时只记录当前 URL，不改任何东西）：
#   DOMAIN=sub.example.com   # 要绑的域名
#   PROVIDER=cloudflare       # 目前实现 cloudflare；其他服务商按下面函数格式补
#   CF_ZONE_ID=...           # Cloudflare zone ID
#   CF_TOKEN=...             # 仅改这一条记录的最小权限 API token（Zone:DNS:Edit，限单个 zone）
# 注意：token 存在 InstaBox 上，平台对机器全可见，务必用最小权限 token，不要用全局 API key。

DIR="$(cd "$(dirname "$0")" && pwd)"
LAST_FILE="$DIR/last_tunnel_url.txt"

CURRENT=$(journalctl -u node2sub-tunnel --no-pager 2>/dev/null | grep -o "https://[a-z0-9-]*\.trycloudflare\.com" | tail -1)
[ -z "$CURRENT" ] && exit 0

LAST=$(cat "$LAST_FILE" 2>/dev/null)
if [ "$CURRENT" = "$LAST" ]; then exit 0; fi

echo "$CURRENT" > "$LAST_FILE"

if [ ! -f "$DIR/dns_config" ]; then
  echo "tunnel URL changed to $CURRENT, no dns_config, DNS not updated"
  exit 0
fi

# shellcheck disable=SC1091
source "$DIR/dns_config"
TARGET=${CURRENT#https://}

if [ "$PROVIDER" = "cloudflare" ]; then
  REC=$(curl -s "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=$DOMAIN&type=CNAME" \
    -H "Authorization: Bearer $CF_TOKEN" | \
    python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('result',[]); print(r[0]['id'] if r else '')" 2>/dev/null)
  if [ -n "$REC" ]; then
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$REC" \
      -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
      --data "{\"type\":\"CNAME\",\"name\":\"$DOMAIN\",\"content\":\"$TARGET\",\"ttl\":120,\"proxied\":false}" > /dev/null
  else
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
      -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
      --data "{\"type\":\"CNAME\",\"name\":\"$DOMAIN\",\"content\":\"$TARGET\",\"ttl\":120,\"proxied\":false}" > /dev/null
  fi
fi

echo "DNS updated: $DOMAIN -> $TARGET"

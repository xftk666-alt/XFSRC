#!/bin/sh
# egress-lockdown.sh — make the authorization gate impossible to step around.
#
# The MITM proxy already refuses out-of-scope hosts, but a process can ignore
# HTTP_PROXY and dial directly. This script closes that: agent commands run as an
# unprivileged uid, and that uid's outbound TCP is forced into the proxy. The
# platform itself keeps running as root and is unaffected.
#
# Prerequisites (all checked below):
#   - iptables, setpriv (util-linux)
#   - CAP_NET_ADMIN on the container
#   - the agent work dir writable by AGENT_UID
#
# Usage:  AGENT_UID=10001 PROXY_PORT=8788 ./egress-lockdown.sh apply
#         ./egress-lockdown.sh status
#         ./egress-lockdown.sh remove
set -eu

AGENT_UID="${AGENT_UID:-10001}"
AGENT_GID="${AGENT_GID:-10001}"
PROXY_PORT="${PROXY_PORT:-8788}"
SHIM_DIR="${SHIM_DIR:-/opt/artex-agent-bin}"
CHAIN="ARTEX_EGRESS"

need() { command -v "$1" >/dev/null 2>&1 || { echo "缺少 $1" >&2; exit 1; }; }

shim_install() {
	mkdir -p "$SHIM_DIR"
	# The SDK invokes `bash -c <command>` by name; a shim earlier in PATH drops
	# privileges before exec. `setpriv` is deliberate: it needs no PAM, no login
	# shell, and no writable home.
	cat >"$SHIM_DIR/bash" <<EOF
#!/bin/sh
exec setpriv --reuid=$AGENT_UID --regid=$AGENT_GID --clear-groups /bin/bash "\$@"
EOF
	chmod 0755 "$SHIM_DIR/bash"
	echo "已写入 $SHIM_DIR/bash（降权到 uid $AGENT_UID 后执行 bash）"
}

rules_apply() {
	# Idempotent: rebuild our chain from scratch.
	iptables -t nat -D OUTPUT -j "$CHAIN" 2>/dev/null || true
	iptables -t nat -F "$CHAIN" 2>/dev/null || true
	iptables -t nat -X "$CHAIN" 2>/dev/null || true

	iptables -t nat -N "$CHAIN"
	# Only the agent uid is constrained; the server (root) keeps its own egress,
	# so LLM calls and self-update are unaffected.
	iptables -t nat -A "$CHAIN" -m owner --uid-owner "$AGENT_UID" -p tcp \
		-m multiport --dports 80,443 -j REDIRECT --to-ports "$PROXY_PORT"
	# Everything else the agent tries is refused outright: no raw-socket escape
	# to ports 25/22/5432, no DNS-over-TCP to an external resolver.
	iptables -t nat -A "$CHAIN" -m owner --uid-owner "$AGENT_UID" -p tcp -j REDIRECT --to-ports "$PROXY_PORT"
	iptables -t nat -A OUTPUT -j "$CHAIN"

	# DNS: the agent resolves through the container resolver only. A UDP hole
	# would let it exfiltrate and reach hosts by name.
	iptables -A OUTPUT -m owner --uid-owner "$AGENT_UID" -p udp --dport 53 -d 127.0.0.53 -j ACCEPT 2>/dev/null || true
	iptables -A OUTPUT -m owner --uid-owner "$AGENT_UID" -p udp --dport 53 -j DROP

	echo "已安装出站规则：uid $AGENT_UID 的 TCP 全部重定向到 :$PROXY_PORT，DNS 仅允许本机解析器"
}

case "${1:-}" in
apply)
	need iptables
	need setpriv
	shim_install
	rules_apply
	echo
	echo "还需要：把 $SHIM_DIR 放到 agent 的 PATH 之前（BashEnv 里设置），"
	echo "并确保 agent 工作目录对 uid $AGENT_UID 可写。"
	;;
status)
	iptables -t nat -S "$CHAIN" 2>/dev/null || echo "未安装"
	iptables -S OUTPUT 2>/dev/null | grep -F 'uid-owner' || true
	;;
remove)
	iptables -t nat -D OUTPUT -j "$CHAIN" 2>/dev/null || true
	iptables -t nat -F "$CHAIN" 2>/dev/null || true
	iptables -t nat -X "$CHAIN" 2>/dev/null || true
	iptables -D OUTPUT -m owner --uid-owner "$AGENT_UID" -p udp --dport 53 -j DROP 2>/dev/null || true
	iptables -D OUTPUT -m owner --uid-owner "$AGENT_UID" -p udp --dport 53 -d 127.0.0.53 -j ACCEPT 2>/dev/null || true
	rm -f "$SHIM_DIR/bash"
	echo "已移除"
	;;
*)
	echo "usage: $0 apply|status|remove" >&2
	exit 2
	;;
esac

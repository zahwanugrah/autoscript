#!/bin/bash

apt update
apt upgrade -y

today=$(date -d +1day +%Y-%m-%d)

while read expired
do
	user=$(echo $expired | awk '{print $1}')
	uuid=$(echo $expired | awk '{print $2}')
	exp=$(echo $expired | awk '{print $3}')

	if [[ $exp < $today ]]; then
		cat /usr/local/etc/v2ray/ws-tls.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' > /usr/local/etc/v2ray/ws-tls_tmp.json
		mv -f /usr/local/etc/v2ray/ws-tls_tmp.json /usr/local/etc/v2ray/ws-tls.json
		cat /usr/local/etc/v2ray/ws.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' > /usr/local/etc/v2ray/ws_tmp.json
		mv -f /usr/local/etc/v2ray/ws_tmp.json /usr/local/etc/v2ray/ws.json
		sed -i "/\b$user\b/d" /data/v2ray/v2ray-clients.txt
	fi
done < /data/v2ray/v2ray-clients.txt

unset expired
while read expired
do
	user=$(echo $expired | awk '{print $1}')
	exp=$(echo $expired | awk '{print $3}')

	if [[ $exp < $today ]]; then
		sed -i "/^### Client ${user}\$/,/^$/d" /etc/wireguard/wg0.conf
		if grep -q "### Client" /etc/wireguard/wg0.conf; then
			line=$(grep -n AllowedIPs /etc/wireguard/wg0.conf | tail -1 | awk -F: '{print $1}')
			head -${line} /etc/wireguard/wg0.conf > /tmp/wg0.conf
			mv /tmp/wg0.conf /etc/wireguard/wg0.conf
		else
			head -7 /etc/wireguard/wg0.conf > /tmp/wg0.conf
			mv /tmp/wg0.conf /etc/wireguard/wg0.conf
		fi
		rm -f /data/wireguard/${user}.conf
		sed -i "/\b$user\b/d" /data/wireguard/wireguard-clients.txt
	fi
done < /data/wireguard/wireguard-clients.txt

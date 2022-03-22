#!/bin/bash

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!"
   exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
   echo "OpenVZ is not supported!"
   exit 1
fi

# Get domain
clear
echo -e "Install variant :"
echo -e "  [1] Xray - Faster (443)"
echo -e "  [2] V2Ray - Support no-TLS (443 & 80)"
echo -e ""
until [[ ${variant} =~ ^[1-2]$ ]]; do
	read -rp "Select an option [1-2]: " variant
done
echo -e ""
read -p "Please enter your domain : " domain
echo -e ""
ip=$(wget -qO- ipv4.icanhazip.com)
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "IP matched with the server. The installation will continue."
	sleep 2
	clear
else
	echo -e "IP does not match with the server. Make sure to point A record to your server."
	echo -e ""
	exit 1
fi

# Update & Upgrade
apt update
apt upgrade -y

# Remove unused dependencies
apt autoremove -y

# Set timezone
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

# Install BBR+FQ
echo -e "net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# Configure UFW
apt install -y ufw
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
sed -i "s/IPV6=yes/IPV6=no/g" /etc/default/ufw
ufw allow 22
ufw allow 85
ufw allow 465
ufw allow 8080
ufw allow 1194
ufw allow 80
ufw allow 443
ufw allow 51820
ufw allow 7300
ufw allow 8000
ufw allow 3128
ufw reload
echo -e "y" | ufw enable

# Install tools
apt install -y net-tools vnstat unzip curl screen

# Install screenfetch
wget -qO /usr/bin/screenfetch "https://raw.githubusercontent.com/iriszz-official/autoscript/main/FILES/screenfetch.sh"
chmod +x /usr/bin/screenfetch
echo -e "clear
screenfetch
echo" >> .profile

# Install variant
if [ "$variant" == 1 ]; then
	# Install Xray
	apt-get install -y lsb-release gnupg2 wget lsof tar unzip curl libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev jq nginx uuid-runtime
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
	echo $domain > /usr/local/etc/xray/domain
	wget -qO /usr/local/etc/xray/config.json "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/xray/xray.json"
	wget -qO /etc/nginx/conf.d/${domain}.conf "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/xray/web.conf"
	sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
	wget -qO web.tar.gz "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/web.tar.gz"
	rm -rf /var/www/html/*
	tar xzf web.tar.gz -C /var/www/html
	rm -f web.tar.gz
	mkdir /data/xray
	curl -L get.acme.sh | bash
	/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
	sed -i "6s/^/#/" /etc/nginx/conf.d/${domain}.conf
   sed -i "6a\\\troot /var/www/html/;" /etc/nginx/conf.d/${domain}.conf
	systemctl restart nginx
	/root/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html/" -k ec-256 --force
	/root/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/xray/xray.crt --keypath /data/xray/xray.key --reloadcmd "systemctl restart xray" --ecc --force
	sed -i "7d" /etc/nginx/conf.d/${domain}.conf
	sed -i "6s/#//" /etc/nginx/conf.d/${domain}.conf
	chown -R nobody.nogroup /data/xray/xray.crt
	chown -R nobody.nogroup /data/xray/xray.key
	touch /iriszz/xray/xray-clients.txt
	sed -i "s/\tinclude \/etc\/nginx\/sites-enabled\/\*;/\t# include \/etc\/nginx\/sites-enabled\/\*;asd/g" /etc/nginx/nginx.conf
	mkdir /etc/systemd/system/nginx.service.d
	printf "[Service]\nExecStartPost=/bin/sleep 0.1\n" | tee /etc/systemd/system/nginx.service.d/override.conf
	systemctl daemon-reload
	systemctl restart nginx
	systemctl restart xray
elif [[ "$variant" == 2 ]]; then
	# Install V2Ray
	apt-get install -y jq uuid-runtime socat
	bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
	echo $domain > /usr/local/etc/v2ray/domain
	wget -qO /usr/local/etc/v2ray/ws-tls.json "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/v2ray/v2ray-ws-tls.json"
	wget -qO /usr/local/etc/v2ray/ws.json "https://raw.githubusercontent.com/iriszz-official/autoscript/main/FILES/v2ray/v2ray-ws.json"
	sed -i "s/xx/${domain}/g" /usr/local/etc/v2ray/ws-tls.json
	sed -i "s/xx/${domain}/g" /usr/local/etc/v2ray/ws.json
	mkdir /iriszz/v2ray
	curl -L get.acme.sh | bash
	/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
	/root/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force
	/root/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray/v2ray.crt --keypath /data/v2ray/v2ray.key --ecc --force
	chown -R nobody.nogroup /data/v2ray/v2ray.crt
	chown -R nobody.nogroup /data/v2ray/v2ray.key
	touch /iriszz/v2ray/v2ray-clients.txt
	systemctl enable v2ray@ws-tls
	systemctl enable v2ray@ws
	systemctl start v2ray@ws-tls
	systemctl start v2ray@ws


# Install BadVPN UDPGw
cd
apt install -y cmake
wget -qO badvpn.zip "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/badvpn.zip"
unzip badvpn.zip
cd badvpn-master
mkdir build-badvpn
cd build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -r badvpn-master
rm badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# Install Speedtest cli
curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash
apt install speedtest

# Install fail2ban
apt install -y fail2ban
service fail2ban restart

# Install DDoS Deflate
apt install -y dnsutils tcpdump dsniff grepcidr
wget -qO ddos.zip "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/ddos-deflate.zip"
unzip ddos.zip
cd ddos-deflate
chmod +x install.sh
./install.sh
cd
rm -rf ddos.zip ddos-deflate

# Configure script
wget -qO /usr/bin/menu "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/menu.sh"
wget -qO /usr/bin/ssh-vpn-script "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/ssh-vpn-script.sh"
if [[ "$variant" == 1 ]]; then
	wget -qO /usr/bin/menu "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/menu-xray.sh"
	wget -qO /usr/bin/xray-script "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/xray-script.sh"
	chmod +x /usr/bin/xray-script
elif [[ "$variant" == 2 ]]; then
	wget -qO /usr/bin/menu "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/menu-v2ray.sh"
	wget -qO /usr/bin/v2ray-script "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/v2ray-script.sh"
	chmod +x /usr/bin/v2ray-script
fi
wget -qO /usr/bin/wireguard-script "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/wireguard-script.sh"
wget -qO /usr/bin/script-info "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/menu/script-info.sh"
wget -qO /usr/bin/script-1 "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/cron/script-1.sh"
if [[ "$variant" == 1 ]]; then
	wget -qO /usr/bin/script-2 "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/cron/script-2-xray.sh"
elif [[ "$variant" == 2 ]]; then
	wget -qO /usr/bin/script-2 "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/cron/script-2-v2ray.sh"
fi
wget -qO /usr/bin/script-3 "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/cron/script-3.sh"
chmod +x /usr/bin/{menu,ssh-vpn-script,wireguard-script,script-info,script-1,script-2,script-3}

# Configure rc.local
wget -qO /etc/rc.local "https://raw.githubusercontent.com/zahwanugrah/autoscript/main/FILES/rc.local"
chmod +x /etc/rc.local

# Configure crontab
echo "0 0 * * * root reboot" >> /etc/crontab
echo "55 23 * * * root script-2" >> /etc/crontab

# Configure block all connections
echo off >> /iriszz/block-status

# Cleanup and reboot
rm -f /root/install.sh
cp /dev/null /root/.bash_history
clear
echo -e ""
echo -e "Script executed succesfully."
echo -e ""
read -n 1 -r -s -p $"Press enter to reboot..."
echo -e ""
reboot

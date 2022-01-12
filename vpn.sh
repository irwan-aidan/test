#!/bin/bash
#
# By MYTEAM
# ==================================================

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ifconfig.me/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Install OpenVPN dan Easy-RSA
apt-get install -y openvpn
wget -q https://github.com/iriszz-official/autoscript/raw/main/FILES/openvpn/EasyRSA-3.0.8.tgz
tar xvf EasyRSA-3.0.8.tgz
rm EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_COUNTRY\t"US"|set_var EASYRSA_REQ_COUNTRY\t"MY"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_PROVINCE\t"California"|set_var EASYRSA_REQ_PROVINCE\t"Selangor"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_CITY\t"San Francisco"|set_var EASYRSA_REQ_CITY\t"Gombak"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"|set_var EASYRSA_REQ_ORG\t\t"Aidan VPN"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_EMAIL\t"me@example.net"|set_var EASYRSA_REQ_EMAIL\t"irwanmohi@gmail.com"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"|set_var EASYRSA_REQ_OU\t\t"Aidan VPN Premium"|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_CA_EXPIRE\t3650|set_var EASYRSA_CA_EXPIRE\t3650|g' /etc/openvpn/easy-rsa/vars
sed -i 's|#set_var EASYRSA_CERT_EXPIRE\t825|set_var EASYRSA_CERT_EXPIRE\t3650|g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
wget -qO /etc/openvpn/server-udp.conf "https://github.com/iriszz-official/autoscript/raw/main/FILES/openvpn/server-udp.conf"
wget -qO /etc/openvpn/server-tcp.conf "https://github.com/iriszz-official/autoscript/raw/main/FILES/openvpn/server-tcp.conf"
sed -i "s|#AUTOSTART="all"|AUTOSTART="all"|g" /etc/default/openvpn
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp

# Configure OpenVPN client configuration
mkdir /root/ovpn-config
wget -qO /root/ovpn-config/client-udp.ovpn "https://github.com/iriszz-official/autoscript/raw/main/FILES/openvpn/client-udp.ovpnn"
wget -qO /root/ovpn-config/client-tcp.ovpn "https://github.com/iriszz-official/autoscript/raw/main/FILES/openvpn/client-tcp.ovpn"
echo "" >> /root/ovpn-config/client-tcp.ovpn
echo "<ca>" >> /root/ovpn-config/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /root/ovpn-config/client-tcp.ovpn
echo "</ca>" >> /root/ovpn-config/client-tcp.ovpn
echo "" >> /root/ovpn-config/client-udp.ovpn
echo "<ca>" >> /root/ovpn-config/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /root/ovpn-config/client-udp.ovpn
echo "</ca>" >> /root/ovpn-config/client-udp.ovpn
cp /root/ovpn-config/client-tcp.ovpn /home/vps/public_html/client-tcp.ovpn
cp /root/ovpn-config/client-udp.ovpn /home/vps/public_html/client-udp.ovpn

iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules

iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# Restart service openvpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart

 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://github.com/korn-sudo/Project-Fog/raw/main/files/plugins/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
 yNginxC

# Creating vps config for our OCS Panel
cat <<'myvpsC' > /etc/nginx/conf.d/vps.conf
server {
  listen       Nginx_Port;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:Php_Socket;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}

myvpsC

# Creating monitoring config for our OpenVPN Monitoring Panel
cat <<'myMonitoringC' > /etc/nginx/conf.d/monitoring.conf

server {
    listen Fog_Openvpn_Monitoring;
    location / {
        uwsgi_pass unix:///run/uwsgi/app/openvpn-monitor/socket;
        include uwsgi_params;
    }
}

myMonitoringC

#this is the home page of our webserver
wget -O /home/vps/public_html/index.php "https://raw.githubusercontent.com/korn-sudo/Project-Fog/main/files/panel/index.php"


# Setting up our WebServer Ports and IP Addresses
cd
sleep 1

sed -i "s|/run/php/php7.0-fpm.sock|127.0.0.1:$Php_Socket|g" /etc/php/7.0/fpm/pool.d/www.conf
sed -i "s|Php_Socket|$Php_Socket|g" /etc/nginx/conf.d/vps.conf
sed -i "s|Nginx_Port|$Nginx_Port|g" /etc/nginx/conf.d/vps.conf
sed -i "s|Fog_Openvpn_Monitoring|$Fog_Openvpn_Monitoring|g" /etc/nginx/conf.d/monitoring.conf
sed -i "s|Fog_Openvpn_Monitoring|$Fog_Openvpn_Monitoring|g" /home/vps/public_html/index.php
sed -i "s|fogserverip|$IPADDR|g" /home/vps/public_html/index.php
sed -i "s|v2portas|65432|g" /home/vps/public_html/index.php

sed -i "s|SSH_Port1|$SSH_Port1|g" /home/vps/public_html/index.php
sed -i "s|SSH_Port2|$SSH_Port2|g" /home/vps/public_html/index.php
sed -i "s|Dropbear_Port1|$Dropbear_Port1|g" /home/vps/public_html/index.php
sed -i "s|Dropbear_Port2|$Dropbear_Port2|g" /home/vps/public_html/index.php
sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /home/vps/public_html/index.php
sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /home/vps/public_html/index.php
sed -i "s|Stunnel_Port3|$Stunnel_Port3|g" /home/vps/public_html/index.php
sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /home/vps/public_html/index.php
sed -i "s|Privoxy_Port2|$Privoxy_Port1|g" /home/vps/public_html/index.php
sed -i "s|Squid_Port1|$Squid_Port1|g" /home/vps/public_html/index.php
sed -i "s|Squid_Port2|$Squid_Port2|g" /home/vps/public_html/index.php
sed -i "s|Squid_Port3|$Squid_Port3|g" /home/vps/public_html/index.php
sed -i "s|OHP_Port1|$OHP_Port1|g" /home/vps/public_html/index.php
sed -i "s|OHP_Port2|$OHP_Port2|g" /home/vps/public_html/index.php
sed -i "s|OHP_Port3|$OHP_Port3|g" /home/vps/public_html/index.php
sed -i "s|OHP_Port4|$OHP_Port4|g" /home/vps/public_html/index.php
sed -i "s|OHP_Port5|$OHP_Port5|g" /home/vps/public_html/index.php
sed -i "s|Simple_Port1|$Simple_Port1|g" /home/vps/public_html/index.php
sed -i "s|Simple_Port2|$Simple_Port2|g" /home/vps/public_html/index.php
sed -i "s|Direct_Port1|$Direct_Port1|g" /home/vps/public_html/index.php
sed -i "s|Direct_Port2|$Direct_Port2|g" /home/vps/public_html/index.php
sed -i "s|Open_Port1|$Open_Port1|g" /home/vps/public_html/index.php
sed -i "s|Open_Port2|$Open_Port2|g" /home/vps/public_html/index.php
sed -i "s|NXPort|$Nginx_Port|g" /home/vps/public_html/index.php

service nginx restart


# Setting Up OpenVPN monitoring
wget -O /srv/openvpn-monitor.zip "https://github.com/korn-sudo/Project-Fog/raw/main/files/panel/openvpn-monitor.zip"
cd /srv
unzip -qq openvpn-monitor.zip
rm -f openvpn-monitor.zip
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt

#updating ports for openvpn monitoring
 sed -i "s|Tcp_Monitor_Port|$Tcp_Monitor_Port|g" /srv/openvpn-monitor/openvpn-monitor.conf
 sed -i "s|Udp_Monitor_Port|$Udp_Monitor_Port|g" /srv/openvpn-monitor/openvpn-monitor.conf


# Creating monitoring .ini for our OpenVPN Monitoring Panel
cat <<'myMonitorINI' > /etc/uwsgi/apps-available/openvpn-monitor.ini
[uwsgi]
base = /srv
project = openvpn-monitor
logto = /var/log/uwsgi/app/%(project).log
plugins = python
chdir = %(base)/%(project)
virtualenv = %(chdir)
module = openvpn-monitor:application
manage-script-name = true
mount=/openvpn-monitor=openvpn-monitor.py
myMonitorINI

ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/

# GeoIP For OpenVPN Monitor
mkdir -p /var/lib/GeoIP
wget -O /var/lib/GeoIP/GeoLite2-City.mmdb.gz "https://github.com/korn-sudo/Project-Fog/raw/main/files/panel/GeoLite2-City.mmdb.gz"
gzip -d /var/lib/GeoIP/GeoLite2-City.mmdb.gz

# Now creating all of our OpenVPN Configs 

# Smart Giga Games Promo TCP
cat <<Config1> /home/vps/public_html/Smart.Giga.Games.ovpn
# Created by blackestsaint

client
dev tun
proto tcp
setenv FRIENDLY_NAME "Server-Name"
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0

http-proxy $IPADDR $Squid_Port1
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER Host codm.garena.com
http-proxy-option CUSTOM-HEADER X-Forward-Host codm.garena.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For codm.garena.com
http-proxy-option CUSTOM-HEADER Referrer codm.garena.com

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config1


# Delete script
history -c
rm -f /root/vpn.sh

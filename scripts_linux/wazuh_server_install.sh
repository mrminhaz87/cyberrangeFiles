#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing curl"
apt install curl -y

echo "Downloading Wazuh Installer Assistant"
curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.3/config.yml

# Installing yq
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq

# setting IPs to the config file
/usr/bin/yq -i '.nodes.indexer[0].ip="192.168.38.106"' config.yml
/usr/bin/yq -i '.nodes.server[0].ip="192.168.38.106"' config.yml
/usr/bin/yq -i '.nodes.dashboard[0].ip="192.168.38.106"' config.yml

# Generating the config file
bash wazuh-install.sh --generate-config-files

echo "Installing Wazuh"
# Starting indexer
# curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh
bash wazuh-install.sh --wazuh-indexer node-1
bash wazuh-install.sh --start-cluster

# Starting server 
bash wazuh-install.sh --wazuh-server wazuh-1

# Starting dashboard
bash wazuh-install.sh --wazuh-dashboard dashboard

# Setting Password
# tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
curl -so wazuh-passwords-tool.sh https://packages.wazuh.com/4.3/wazuh-passwords-tool.sh
bash wazuh-passwords-tool.sh -u admin -p Admin-1234

echo "Installation Complete"
echo "user: admin, pass: Admin-1234"

# decoder and rule for sysmon-for-linux
# as shown in: https://www.youtube.com/watch?v=y5K1pctFoaw
echo "Storing the rules and decoders into the guest machine"
cp /vagrant/resources/sysmon/sysmon-for-linux/wazuh-decoders/* /var/ossec/etc/decoders/
cp /vagrant/resources/sysmon/sysmon-for-linux/wazuh-rules/* /var/ossec/etc/rules/

echo "Connecting to Elastic search at: 192.168.38.105:9200"
#/usr/bin/yq -i '.output.elasticsearch.hosts[0]="192.168.38.105:9200"' /etc/filebeat/filebeat.yml
sed -i 's/192.168.38.106/192.168.38.105/' /etc/filebeat/filebeat.yml


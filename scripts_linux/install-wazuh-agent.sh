#!/bin/bash
# Purpose of this script is install wazuh agent

echo "Installing Sysmon"
# Register Microsoft key and feed
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb

apt-get update
apt-get install sysmonforlinux -y
sysmon -i -accepteula 

echo "Configuring Sysmon"
# This one may not work, need conf file for linux
# wget https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml

cp /vagrant/resources/sysmon/sysmon-for-linux/config.xml /opt/config.xml
sysmon -c /opt/config.xml

echo "Installing curl"
apt-get install curl -y
echo "Installing wazuh agent"
curl -so wazuh-agent-3.13.1.deb https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-agent/wazuh-agent_3.13.1-1_amd64.deb && WAZUH_MANAGER='192.168.2.110' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-3.13.1.deb

/var/ossec/bin/agent-auth -m 192.168.2.110

echo "Starting the service"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent





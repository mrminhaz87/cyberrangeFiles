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

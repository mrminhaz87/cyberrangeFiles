#! /bin/bash

echo "Updating the repository"
apt update &> /dev/null
echo "Installing curl and other essential tools"
apt install curl -y
apt install build-essential pkg-config bison flex autoconf automake libtool make nodejs git -y

echo "Downloading and installing OpenPLCv3"
git clone https://github.com/thiagoralves/OpenPLC_v2.git
cd OpenPLC_v2

# Omitting read inputs, beacuse...
echo "EDiting the build.sh file to omit manual input"
sed -i 's/read DNP3_SUPPORT/DNP3_SUPPORT="y"/' "build.sh"
sed -i 's/sudo apt-get install cmake/sudo apt-get install cmake -y/' "build.sh"
sed -i 's/select opt in $OPTIONS; do/opt="Modbus"/' "build.sh"
sed -i 's/done//' "build.sh"

./build.sh

echo "Starting the web server"
nodejs server.js &

# For future startups
cp /vagrant/resources/openplcv2/opplcv2_servers_start.sh /etc/init.d/
chmod 755 /etc/init.d/opplcv2_servers_start.sh
update-rc.d opplcv2_servers_start.sh defaults


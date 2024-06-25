#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing curl"
apt install curl -y

echo "Downloading and installing OpenPLCv3"
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3
./install.sh linux

echo "rebooting..."
reboot



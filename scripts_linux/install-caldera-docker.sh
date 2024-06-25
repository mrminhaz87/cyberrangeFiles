#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing git"
apt install git -y

echo "Installing docker"
apt-get install -y docker.io docker-compose

echo "Downloading and installing caldera"
git clone https://github.com/mitre/caldera.git --recursive --branch 4.0.0
cd caldera
sed -i 's/pyminizip==0.2.4/pyminizip==0.2.6/' requirements.txt
sed -i '34 a- emu' conf/default.yml
sed -i '10 a\    restart: always' docker-compose.yml # starts at boot

docker-compose build
docker-compose up &

echo "Caldera server started at port 8888 with below credentials"
cat conf/local.yml | grep \ blue:
cat conf/local.yml | grep \ red:

reboot

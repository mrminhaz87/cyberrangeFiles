#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing git"
apt install git -y
echo "Installing pip3"
apt install python3-pip -y

if [ -d "caldera" ] 
then
    echo "caldera already installed" 
    cd caldera
else
    echo "Downloading and installing caldera"
    git clone https://github.com/mitre/caldera.git --recursive --branch 4.0.0
    cd caldera
    sed -i 's/pyminizip==0.2.4/pyminizip==0.2.6/' requirements.txt
    sed -i '34 a- emu' conf/default.yml
    pip3 install -r requirements.txt
    
    if [[ ":$PATH:" == *":/home/vagrant/.local/bin:"* ]]
    then
        echo "Path already included"
    else
        export PATH="/home/vagrant/.local/bin:$PATH"
    fi
fi

echo "starting caldera server at port 8888"
python3 server.py --insecure &
# For future startups
cp /vagrant/resources/caldera/servers_start.sh /etc/init.d/
chmod 755 /etc/init.d/servers_start.sh
update-rc.d servers_start.sh defaults

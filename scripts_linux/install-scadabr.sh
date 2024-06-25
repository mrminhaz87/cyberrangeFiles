#! /bin/bash

echo "Updating the repository\n"
apt update
echo "Installing curl\n"
apt install curl -y

if [ -d "ScadaBR_Installer" ] 
then
    echo "ScadaBR already installed" 
else
    echo "Downloading and installing ScadaBR\n"
    git clone https://github.com/thiagoralves/ScadaBR_Installer.git
    cd ScadaBR_Installer
    ./install_scadabr.sh
fi

# The doc says, "just make sure you log into the tool at least once before doing so or you could en up with a corrupt installation", so commenting this out, for now
# ./update_scadabr.sh

# For future startups
cp /vagrant/resources/scadabr/tomcat-server-start.sh /etc/init.d/
chmod 755 /etc/init.d/tomcat-server-start.sh
update-rc.d tomcat-server-start.sh defaults

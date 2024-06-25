#!/bin/bash
# Purpose of this script is getting ready the simulation

apt-get update &> /dev/null

echo "Installing pre-requisites"
apt-get install git -y
apt-get install libjsoncpp-dev liblapacke-dev python3-pymodbus -y  &> /dev/null
apt-get install build-essential -y

echo "Creating the chemical plant simulation"
git clone https://github.com/Fortiphyd/GRFICSv2
cd GRFICSv2/simulation_vm/simulation
make

echo "Installing web visualization tools"
apt install apache2 php libapache2-mod-php -y
rm /var/www/html/index.html
ln -s /home/vagrant/GRFICSv2/simulation_vm/web_visualization/* /var/www/html

# We don't need the following, as we are using our own defined ip addresses

#echo "copying network configuration from vagrant/resources/chemicalplant/interfaces"
#cp /vagrant/resources/chemicalplant/interfaces /etc/network/interfaces

#echo "Restarting network"
#systemctl restart systemd-networkd

echo "Fixing simulation issues"
# Tried to downgrade the system, to match the code.
# But then thought, "let's not do it"
#wget http://archive.ubuntu.com/ubuntu/pool/universe/p/pymodbus/python-pymodbus_1.3.2-1_all.deb
#dpkg -i python-pymodbus_1.3.2-1_all.deb

# upgrading the outdated codes
apt install python-is-python3 -y
apt install 2to3 -y

# Fixing the run_all.sh file
sed -i 's/user/vagrant/' /home/vagrant/GRFICSv2/simulation_vm/simulation/remote_io/modbus/run_all.sh

# Fixing python import of pymodbus.client.async
cd /home/vagrant/GRFICSv2/simulation_vm/simulation/remote_io/modbus/
sed -i 's/pymodbus.server.async/pymodbus.server.asynchronous/' feed1.py feed2.py analyzer.py tank.py purge.py product.py remote_io.py

# Converting from python2 to python3 code
2to3 -w feed1.py feed2.py analyzer.py tank.py purge.py product.py remote_io.py &> /dev/null

# Fixing IP addresses
sed -i 's/192.168.95/192.168.40/' feed1.py feed2.py analyzer.py tank.py purge.py product.py remote_io.py

sed -i "s/s.send('/s.send(b'/" feed1.py feed2.py analyzer.py tank.py purge.py product.py remote_io.py
sed -i "s/repr(current_command)+'}}/repr(current_command).encode()+b'}}/" feed1.py feed2.py analyzer.py tank.py purge.py product.py remote_io.py

echo "Starting the simulations"
/home/vagrant/GRFICSv2/simulation_vm/simulation/simulation &
bash /home/vagrant/GRFICSv2/simulation_vm/simulation/remote_io/modbus/run_all.sh &

# For future startups
cp /vagrant/resources/chemicalplant/sim_servers_start.sh /etc/init.d/
chmod 755 /etc/init.d/sim_servers_start.sh
update-rc.d sim_servers_start.sh defaults




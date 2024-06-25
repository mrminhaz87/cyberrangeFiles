#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing git"
apt-get install git -y

echo "Downloading and installing caldera"
# apt-get update
apt-get install python3 -y 
apt-get install ansible -y

git clone https://github.com/abdulazizag/Virtual-Machine-and-Container-based-Deployment-of-5G-using-Ansible-with-Security-Implementation.git
cd Virtual-Machine-and-Container-based-Deployment-of-5G-using-Ansible-with-Security-Implementation
cd Docker\ Deployment\ with\ IPsec
sed -i 's/ubuntu {{ansible_distribution_release}} edge/ubuntu focal stable/' Ansible_5G_deployment.yml
echo "Running Ansible_5G_deployment.yml with network_interface=eth1"
ansible-playbook -K Ansible_5G_deployment.yml -e "internet_network_interface=eth1"

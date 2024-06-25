#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing git"
apt-get install git -y

echo "Downloading and installing PLC Editor"
git clone https://github.com/thiagoralves/OpenPLC_Editor
cd OpenPLC_Editor

# the location is different here
sed -i 's/~\/.local\/share\/applications/\/usr\/share\/applications/' install.sh

# Starting installation
./install.sh

echo "Cloning the GRFICSV2 repo that has demo plc scripts"
git clone https://github.com/Fortiphyd/GRFICSv2

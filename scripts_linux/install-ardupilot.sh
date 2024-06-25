#! /bin/bash

echo "Updating the repository"
apt update &> /dev/null
echo "Installing other essential tools"
apt install curl git -y




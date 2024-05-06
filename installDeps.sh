#!/bin/bash
echo "Setting kernel params..."
echo ""
sudo sysctl -w fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w fs.inotify.max_user_instances=1048576 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w fs.aio-max-nr=1048576 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w fs.file-max=9223372036854775807 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=128 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.neigh.default.gc_thresh2=4096 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=8192 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

echo "Installing dependencies..."
echo ""
sudo apt-get update
sudo apt-get install unzip wireguard wireguard-dkms nginx curl certbot python3-certbot-nginx

#Installing docker
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
# Installing vbox v7.0.14 release
wget https://download.virtualbox.org/virtualbox/7.0.14/virtualbox-7.0_7.0.14-161095~Ubuntu~jammy_amd64.deb
wget https://download.virtualbox.org/virtualbox/7.0.14/Oracle_VM_VirtualBox_Extension_Pack-7.0.14.vbox-extpack

sudo dpkg -i virtualbox-7.0_7.0.14-161095~Ubuntu~jammy_amd64.deb
sudo apt install -f -y

echo "y" | sudo vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-7.0.14.vbox-extpack
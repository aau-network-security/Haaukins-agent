#!/bin/bash

echo ""
echo "Setting up the haaukins user"
echo ""
sudo useradd -m haaukins
sudo chown -R haaukins:haaukins /home/haaukins
sudo chmod 750 /home/haaukins
sudo mkdir /home/haaukins/.ssh
sudo chmod 700 /home/haaukins/.ssh
sudo touch /home/haaukins/.ssh/authorized_keys
sudo chmod 644 /home/haaukins/.ssh/authorized_keys
sudo cat /home/$USER/.ssh/authorized_keys | sudo tee -a /home/haaukins/.ssh/authorized_keys
sudo chown haaukins:haaukins -R /home/haaukins/.ssh
#sudo usermod -aG haaukins $USER
sudo chown -R haaukins:haaukins /etc/wireguard
sudo usermod -aG docker haaukins

sudo echo "haaukins ALL=(ALL) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/sbin/iptables" | sudo tee -a /etc/sudoers

sudo echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/su haaukins" | sudo tee -a /etc/sudoers

sudo chsh -s /bin/bash haaukins
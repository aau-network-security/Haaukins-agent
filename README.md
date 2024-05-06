# Haaukins-agent
The Haaukins agent is a key component in Haaukins 2.0. It takes care of spinning up and managing virtual labs (VPN or browser based) using VirtualBox, Wireguard and docker. 

In a full Haaukins 2.0 setup you can have several agents. The [Haaukins Daemon](https://github.com/aau-network-security/haaukins-daemon) will connect to each agent with gRPC and distribute labs based on weighted round robin but will also take care of not over provisioning the agent by taking the available memory into account. 

## Setting up an agent
This setup guide is based on running the Agent on Ubuntu 22.04  
The Agent uses several dependencies which must be installed before setting up the actual Agent.

### Installing dependencies
* Wireguard
* Nginx and Certbot
* VirtualBox including the accompanying expansion package
* Docker
* The [Gwireguard](https://github.com/aau-network-security/gwireguard/tree/bugfix/fix-delpeer-function) service  
It is important that the `bugfix/fix-delpeer-function` branch is used.

`Gwireguard` has to be set up according to it's github page.

The rest of the dependencies can be installed using the [installDeps](installDeps.sh) script placed in this repo. The script will also set a bunch of kernel parameters optimized for running an Agent. The script can be edited if another version of VirtualBox is desired

### Setting up a `haaukins` user
For the actual set up of the Agent we recommend creating a `haaukins` user.
This is because that the user running the Agent should have access to run `wg`, `wg-quick` and `iptables` as sudo with no password. It is therefore also important that the server used for running the agent should not be used for any sensitive tasks. We also recommend running the agent in an isolated network as this should be seen as an untrusted environment with high risk of compromise if used by the general public.
The `haaukins` user also needs to become the owner of the `/etc/wireguard` folder in order to write interface configurations etc.

You can use the [setupHaaukinsUser](setupHaaukinsUser.sh) script to do everything for you. This will also allow you to ssh into the `haaukins` user which could come in handy when having to upload virtual machines for browser labs.

### Configuring the Agent
If you download and unpack the latest tarball (as the `haaukins` user in it's home folder), the folder structure should be aligned.
Everything needed to run the Agent, except for a VirtualBox VM image, is contained in the haaukins-agent folder after being unpacked. `Nginx` example configs has been included if you wish to setup proxying with SSL. Here `Certbot` can be used to supply the SSL certificates. There is also a `systemd` service file, that if you have unpacked the tarball in the `haaukins` user's home folder, should be directly usable.
Configuration of these things will not be covered as there are plenty of examples elsewhere.  

You will need to know the hostname of the agent. Let's use `agent1.example.com` for this example config. DNS wise you will need two A records, one for `agent1.example.com` and one for `*.agent1.example.com`.

Here is an example of what the config will look like
```yaml
host: agent1.example.com
listening-ip: "127.0.0.1" # "0.0.0.0" if you just want to access the agent without a proxy
grpcPort: 8081
proxyPort: 8082 # This is the port that the agent's built in guacamole proxy will listen on

auth-key: a9c4fee7-a6ae-4611-a451-87971e0f7e71 # use uuidgen on linux to generate
sign-key: c7729d85-2e95-4d9a-8ab3-b03d374a5875 # use uuidgen on linux to generate
max-workers: 5 # We recommend 5 workers, tests have shown that there is no gain in increasing it further.
file-transfer-root: /home/haaukins/haaukins-agent/filetransfer
ova-dir: /home/haaukins/haaukins-agent/vms # Place your vm's for browser labs here, make sure the name without .ova matches what has been configured on the Haaukins Daemon
state-path: /home/haaukins/haaukins-agent

vpn-service: # Config to connect to the Gwireguard service
  endpoint: localhost
  port: 5353
  auth-key: 08ddecbc-5c1a-46fb-b0f3-835deef62024 # Make sure it matches what is inside the Gwireguard config which you configured according to it's github repo
  sign-key: 4c0208b6-241e-4605-b3b2-ec1e0a173ed1 # Make sure it matches what is inside the Gwireguard config which you configured according to it's github repo
  wg-conf-dir: /etc/wireguard
  tls-enabled: false

docker-repositories:
- serveraddress: some-docker-registry.com
  username: some-username-for-said-registry
  password: some-password-for-said-registry
- serveraddress: ghcr.io # This registry has to be included, it is needed to get db docker image for the Apache Guacamole containers. A username and password can be added if used for challenge docker registry.
```


### Ports
Wireguard uses UDP for it's connections.  
Haaukins specifically uses UDP port `5000-6000` when creating wireguard interfaces for it's events. So make sure that these are opened in any firewalls etc.


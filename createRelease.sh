#!/bin/bash

# This script is used to create a release of the project.
# Check if the -h or --help flag is passed
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Usage: $0 <version>"
  echo
  echo "This script is used to create a release of the project."
  echo
  echo "Arguments:"
  echo "  <version>  The version number for the release."
  echo
  echo "Options:"
  echo "  -h, --help  Show this help message and exit."
  exit 0
fi

if [ -z "$1" ]; then
  echo "Error: Please provide the version number as an argument."
  echo "Usage: $0 <version>"
  exit 1
fi

mkdir -p release

# First we build the binary with the version tag
echo "Building the project with version $1"
date=$(date)
go build --ldflags "-X 'main.version=$1' -X 'main.compileDate=$date'" -o release/haaukins-agent-$1-linux-64bit
chmod +x release/haaukins-agent-$1-linux-64bit

# cp assets folder to release
cp -r assets release/

# cp config folder to release
cp -r config release/

# cp nginx folder to release
cp -r nginx release/

# copy templates folder to release
cp -r templates release/

# cp the systemd service file to release
cp haaukins-agent.service release/

# cp cleanup.sh to release
cp cleanup.sh release/

# cd to release folder
cd release

# Create the tarball
echo "Creating the tarball"
tar -czf haaukins-agent-$1-linux-64bit.tar.gz haaukins-agent-$1-linux-64bit assets config nginx haaukins-agent.service templates cleanup.sh

# remove everything exept the build binary and tarball
rm -rf assets config nginx haaukins-agent.service templates cleanup.sh



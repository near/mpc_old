#!/bin/bash
set -exo pipefail

# Takes disk alias and mount path as parameters
function disk_initial_setup {
  # Terraform attaches disks in random (well, not easily determinable) order
  # We first need to figure out device name
  disk_suffix=$1
  path=$2

  # Ensure that we can see attached disk
  echo "Looking for disk by id google*-$disk_suffix..."
  until L=$(readlink /dev/disk/by-id/google*-$disk_suffix)
  do
      sleep 1
  done
  disk=$(realpath /dev/disk/by-id/$L)

  echo Mounting $disk_suffix disk with name $disk to path $path

  # Ensure we can see the attached disk.
  echo "Looking for $disk..."
  until ls $disk
  do
      sleep 1
  done
  
  # Format the device, if necessary.
  until file -s $(realpath $disk) | cut -d , -f1 | grep ext4
  do
      mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard $disk
  done
  
  # Ensure the disk is formatted.
  until file -s $(realpath $disk) | cut -d , -f1 | grep ext4
  do
      echo "Disk not formatted as ext4... exiting!"
      exit 1
  done
  fsck.ext4 -p $disk
  
  # Create a mount point.
  mkdir -p $path 
  # ... and mount.
  mount -o discard,defaults $disk $path

  # this will instantiate UUID variable with disk UUID value
  # $ blkid /dev/sdc | cut -d ' ' -f 2
  # UUID="2b2e50ed-03f9-4831-8922-58d90f5aaaaa"
  eval $(blkid $disk | cut -d ' ' -f 2)

  # Clearing disk from fstab  (if present)
  sed -i -e "\|$disk|d" -e "\|$UUID|d" /etc/fstab
  echo "UUID=$UUID $path ext4 discard,defaults,nofail 0 2" >> /etc/fstab
  
  resize2fs $disk
}

#####################################################################
# Create MPC config.yaml
#####################################################################
write_mpc_config() {
  local config_file=$1
  local ACCOUNT_ID=$2

  touch "$config_file"
  cat <<EOF > "$config_file"
# Configuration File
my_near_account_id: $ACCOUNT_ID
web_ui:
  host: 0.0.0.0
  port: 8080
triple:
  concurrency: 2
  desired_triples_to_buffer: 1000000
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 16
  desired_presignatures_to_buffer: 8192
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: v1.signer-prod.testnet
  port_override: 80
  finality: optimistic
cores: 12
EOF
}

#####################################################################
# Step to assign variables
#####################################################################
echo "Reading instance metadata..."	
eval $(curl -s -H 'Metadata-Flavor: Google' 'metadata/computeMetadata/v1/instance/attributes/?recursive=1' |\
	jq -r '"ACCOUNT_ID=\(.MPC_ACCOUNT_ID // false)
CHAIN_ID=\(.MPC_ENV // false)"')

gce_container_declaration=$(curl -s -H 'Metadata-Flavor: Google' 'metadata/computeMetadata/v1/instance/attributes/?recursive=1' |
jq -r '.["gce-container-declaration"]')

# Fix the JSON string
gce_container_declaration=$(echo "$gce_container_declaration" | sed -e 's/\\n/\n/g' -e 's/\\//g')

# Parse the cleaned JSON string and extract variables
eval $(echo "$gce_container_declaration" | jq -r '.containers[0].env | map(select(.name == "MPC_ACCOUNT_ID" or .name == "MPC_ENV")) | .[] | .name + "=" + .value' | tr '\n' ' ')


ACCOUNT_ID="signer-c436b5b3-f815-4750-938d-1a4b4b87c911.testnet"
MPC_DIR=/home/mpc
DATA_DIR="/home/mpc/data"
CONTRACT="v1.signer-prod.testnet"

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "Variables:"
echo  $ACCOUNT_ID
echo  $CHAIN_ID
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"


#####################################################################
# Disk initial setup
#####################################################################
#If already have some of data dirs then initial setup was already done
# TODO: Improve at skip step of disk attach. Do not exit on this step.
if [ -d "$MPC_DIR/data" ]; then
  echo "Data directory already exist, there is no need to initial setup, exiting..."
  # docker rm watchtower; 
  # docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30
else
  disk_initial_setup mpc-partner-testnet-0 "$MPC_DIR"
  mkdir -p $MPC_DIR/data
fi

#####################################################################
# MPC Config
#####################################################################
if [ -d "$MPC_DIR/data/config.yaml" ]; then
  echo "Neard config is already initialized."
else
  write_mpc_config "$MPC_DIR/data/config.yaml" "$ACCOUNT_ID"
  echo "Neard config is not initialized."
fi



# docker rm watchtower; 
# docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30

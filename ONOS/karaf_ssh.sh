#!/bin/bash

# Prompt user for the port number
read -p "Enter SSH port number: " PORT

# Define SSH command
SSH_CMD="ssh -p $PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa karaf@localhost"

# Run SSH command and capture output
OUTPUT=$($SSH_CMD 2>&1)

# Check if the output contains the host key warning
if echo "$OUTPUT" | grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED"; then
    echo "Host key mismatch detected. Attempting to fix..."
    ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:$PORT"
    
    # Retry the SSH command after removing the old key
    echo "Retrying SSH connection..."
    $SSH_CMD
else
    # Print the SSH output if no host key issue occurred
    echo "$OUTPUT"
fi


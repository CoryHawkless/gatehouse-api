#!/bin/bash

# Script to request user organizations with bearer token
# Usage: ./request_organizations.sh <bearer_token>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <bearer_token>"
    exit 1
fi

TOKEN=$1

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8888/api/v1/users/me/organizations
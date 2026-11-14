#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")/../application"
. ./common.sh
require_docker
require_local_configuration
compose ps -a

# Shared commands. Installation secrets stay outside the source directory.
set_config_path() {
    local_config_file=${ODYSAFE_INSTALL_CONFIG:-${XDG_DATA_HOME:-$HOME/.local/share}/odysafe-url/installation.env}
}
require_docker() {
    command -v docker >/dev/null 2>&1 || { printf '%s\n' 'Docker is not installed. See README.md.' >&2; return 1; }
    docker info >/dev/null || { printf '%s\n' 'Start Docker and check that your account can access it.' >&2; return 1; }
    docker compose version >/dev/null || { printf '%s\n' 'The Docker Compose plugin is required.' >&2; return 1; }
}
require_supported_host() {
    case "$(docker info --format '{{.OSType}}/{{.Architecture}}')" in
        linux/x86_64|linux/amd64) ;;
        *) printf '%s\n' 'This release requires Docker on Linux x86_64.' >&2; return 1;;
    esac
    if ! docker info --format '{{json .SecurityOptions}}' | grep -q apparmor; then
        printf '%s\n' 'AppArmor must be enabled. Windows, macOS and ARM are not validated.' >&2
        return 1
    fi
    # Fast startup probes use Docker's native health start interval (API 1.44+).
    server_api=$(docker version --format '{{.Server.APIVersion}}')
    case "$server_api" in
        1.*)
            api_minor=${server_api#1.}
            if [ "${api_minor%%.*}" -lt 44 ]; then
                printf '%s\n' 'Docker Engine 25 or newer is required. See README.md.' >&2
                return 1
            fi;;
    esac
    if ! docker compose up --help | grep -q -- '--wait'; then
        printf '%s\n' 'Update the Docker Compose plugin: support for up --wait is required.' >&2
        return 1
    fi
}
initialize_local_configuration() {
    set_config_path
    if [ -L "$local_config_file" ]; then printf '%s\n' 'The local configuration must not be a symbolic link.' >&2; return 1; fi
    if [ ! -f "$local_config_file" ]; then
        umask 077
        mkdir -p -- "$(dirname -- "$local_config_file")"
        token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
        [ "${#token}" -eq 64 ] || { printf '%s\n' 'Could not initialize the local secret.' >&2; return 1; }
        (set -C; printf 'ODYSAFE_INSTALL_TOKEN=%s\nODYSAFE_WEB_PORT=8443\nODYSAFE_XPRA_PORT=14500\nODYSAFE_XPRA_INTERNET_PORT=14501\n' "$token" > "$local_config_file")
        unset token
        printf '%s\n' "Local configuration created: $local_config_file"
    fi
}
require_local_configuration() {
    set_config_path
    [ -f "$local_config_file" ] && [ ! -L "$local_config_file" ] || { printf '%s\n' 'Run sh start.dh first to initialize this installation.' >&2; return 1; }
}
compose() {
    docker compose --env-file release-images.env --env-file "$local_config_file" -f compose.json "$@"
}

app_image() {
    compose config --images app
}

# Offline bundles bind local image tags to the audited image IDs.
image_available() {
    actual_image_id=$(docker image inspect --format '{{.Id}}' "$1" 2>/dev/null) || return 1
    if [ -f ../images.ids ]; then
        expected_image_id=$(awk -v image="$1" '$2==image {print $1}' ../images.ids)
        [ "$actual_image_id" = "$expected_image_id" ] || return 1
    fi
}

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
    docker compose --env-file "$local_config_file" -f compose.json "$@"
}

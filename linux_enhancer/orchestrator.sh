#!/usr/bin/env bash
#
# Linux Enhancer GOD-MODE Orchestrator
# Fully autonomous, cross-platform, production-ready
#
# Copyright © 2025 Devin B. Royal.
# All Rights Reserved.
#

set -euo pipefail

LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/orchestrator.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
error_exit() { log "ERROR: $1"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$REPO_ROOT/ansible"
TERRAFORM_DIR="$REPO_ROOT/terraform"
CDK_DIR="$TERRAFORM_DIR/cdk"
VAULT_DIR="$REPO_ROOT/vault"

# ------------------------------
# Dependency Installation
# ------------------------------
install_dependency() {
    local dep="$1"
    local install_cmd="$2"
    if ! command -v "$dep" >/dev/null 2>&1; then
        log "$dep missing. Installing..."
        eval "$install_cmd" || error_exit "Failed to install $dep"
    else
        log "$dep found."
    fi
}

install_vault() {
    if command -v vault >/dev/null 2>&1; then
        log "Vault already installed."
        return
    fi

    OS="$(uname)"
    if [[ "$OS" == "Darwin" ]]; then
        log "Downloading Vault for macOS..."
        VAULT_VERSION="1.15.3"
        curl -o /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_darwin_amd64.zip" || error_exit "Failed to download Vault"
        unzip -o /tmp/vault.zip -d /tmp
        sudo mv /tmp/vault /usr/local/bin/
        rm /tmp/vault.zip
        log "Vault installed to /usr/local/bin"
    elif [[ "$OS" == "Linux" ]]; then
        if command -v apt >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y vault || error_exit "Failed to install Vault via apt"
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y vault || error_exit "Failed to install Vault via yum"
        else
            error_exit "Cannot install Vault automatically on this Linux system"
        fi
    fi
}

bootstrap_dependencies() {
    OS="$(uname)"
    case "$OS" in
        Darwin) PKG_INSTALL="brew install" ;;
        Linux)
            if command -v apt >/dev/null 2>&1; then PKG_INSTALL="sudo apt-get install -y"
            elif command -v yum >/dev/null 2>&1; then PKG_INSTALL="sudo yum install -y"
            else error_exit "Unsupported Linux package manager"; fi
            ;;
        *) error_exit "Unsupported OS: $OS" ;;
    esac

    install_dependency terraform "brew tap hashicorp/tap && brew install hashicorp/tap/terraform || $PKG_INSTALL terraform"
    install_dependency aws "$PKG_INSTALL awscli"
    install_dependency node "$PKG_INSTALL nodejs npm"
    install_dependency cdk "npm install -g aws-cdk"
    install_dependency ansible "$PKG_INSTALL ansible"
    install_vault
}

# ------------------------------
# AWS Credentials
# ------------------------------
setup_aws_credentials() {
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        log "AWS credentials already set in environment."
        return
    fi

    if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then
        log "AWS CLI credentials valid. Using default profile."
        return
    fi

    if command -v vault >/dev/null 2>&1; then
        log "Retrieving AWS credentials from Vault..."
        AWS_ACCESS_KEY_ID=$(vault kv get -field=aws_access_key_id secret/aws || true)
        AWS_SECRET_ACCESS_KEY=$(vault kv get -field=aws_secret_access_key secret/aws || true)
        if [[ -n "$AWS_ACCESS_KEY_ID" && -n "$AWS_SECRET_ACCESS_KEY" ]]; then
            export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
            log "AWS credentials loaded from Vault."
            return
        fi
    fi

    error_exit "No AWS credentials found. Please set env variables or configure Vault."
}

# ------------------------------
# Terraform
# ------------------------------
run_terraform() {
    log "Running Terraform..."
    cd "$TERRAFORM_DIR"
    terraform init -input=false
    terraform apply -auto-approve || error_exit "Terraform apply failed"
    cd "$REPO_ROOT"
}

# ------------------------------
# CDK
# ------------------------------
run_cdk() {
    log "Running CDK..."
    cd "$CDK_DIR"
    npm install || log "CDK npm install failed but continuing"
    cdk deploy --require-approval never || error_exit "CDK deploy failed"
    cd "$REPO_ROOT"
}

# ------------------------------
# Ansible
# ------------------------------
run_ansible() {
    log "Running Ansible Local Playbook..."
    if [ -f "$ANSIBLE_DIR/playbooks/local.yml" ]; then
        ansible-playbook "$ANSIBLE_DIR/playbooks/local.yml" || log "Local playbook errors, continuing..."
    else
        log "Local playbook not found. Skipping."
    fi

    if [ -f "$ANSIBLE_DIR/hosts" ] && [ -f "$ANSIBLE_DIR/playbooks/remote.yml" ]; then
        log "Running Ansible Remote Playbook..."
        ansible-playbook "$ANSIBLE_DIR/playbooks/remote.yml" -i "$ANSIBLE_DIR/hosts" || log "Remote playbook errors, continuing..."
    else
        log "No hosts file or remote playbook found. Skipping remote."
    fi
}

# ------------------------------
# Vault
# ------------------------------
setup_vault() {
    log "Setting up Vault..."
    if [ -f "$VAULT_DIR/policies.hcl" ]; then
        vault policy write enhancer "$VAULT_DIR/policies.hcl" || log "Vault policy may already exist"
    fi
    vault secrets enable -path=secret kv || log "Vault secret path may already exist"
}

# ------------------------------
# Main
# ------------------------------
main() {
    log "=== GOD-MODE Orchestrator Starting ==="
    bootstrap_dependencies
    setup_aws_credentials
    run_terraform
    run_cdk
    run_ansible
    setup_vault
    log "=== GOD-MODE Orchestrator Finished Successfully ==="
}

main "$@"

#!/usr/bin/env python3

import argparse
from base64 import b64encode
from pprint import pformat
import sys

from agithub.GitHub import GitHub
from loguru import logger
from nacl import encoding, public
import yaml

# Small cache of repo pkeys to save some API calls
public_key_cache = {}


def read_secrets_file(filename):
    """Read the YAML configuration file"""
    logger.debug("read_secrets_file")
    secrets = yaml.safe_load(open(filename))
    return secrets


# https://developer.github.com/v3/actions/secrets/#create-or-update-a-secret-for-a-repository
def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def get_repo_public_key(repo_path, github_handle):
    global public_key_cache
    key = {"key_id": "", "key": ""}
    if repo_path in public_key_cache:
        logger.debug(f"Public key cache hit for repo {repo_path}")
        key = public_key_cache[repo_path]
    else:
        logger.debug(f"Public key cache miss for repo {repo_path}")
        owner, repo = repo_path.split("/")
        gh_status, data = github_handle.repos[owner][repo].actions.secrets["public-key"].get()
        if gh_status == 200:
            logger.debug(f"Successfully read private key for repo {repo_path}")
            public_key_cache[repo_path] = data
            key = data
        else:
            logger.error(f"Error reading private key for repo {repo_path} : {gh_status}")
    return key


def secret_exists(repo_path, secret_name, github_handle):
    status = False
    owner, repo = repo_path.split("/")
    if owner and repo:
        gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].get()
        if gh_status == 200:
            status = True
    else:
        logger.error(f"Unable to determine owner and repo from {repo_path}")
    return status


def upsert_secret(repo_path, secret_name, secret_val, github_handle):
    """Add or update a secret in a github repo."""
    status = False
    owner, repo = repo_path.split("/")
    if owner and repo:
        public_key = get_repo_public_key(repo_path, github_handle)
        if public_key["key"]:
            encrypted_secret = encrypt(public_key["key"], secret_val)
            if public_key["key_id"]:
                request_body = {"encrypted_value": encrypted_secret, "key_id": public_key["key_id"]}
                request_headers = {"Content-Type": "application/json"}
                gh_status, data = (
                    github_handle.repos[owner][repo]
                    .actions.secrets[secret_name]
                    .put(body=request_body, headers=request_headers)
                )
                if gh_status in [204, 201]:
                    status = True
                else:
                    logger.error(f"Error upserting secret {repo_path} : {gh_status}")
            else:
                logger.error("No public key ID - unable to upsert secret")
        else:
            logger.error("No public key - unable to upsert secret")
    else:
        logger.error(f"Unable to determine owner and repo from {repo_path}")
    return status


def remove_secret(repo_path, secret_name, github_handle):
    """Remove a secret from a github repo."""
    status = False
    owner, repo = repo_path.split("/")
    if owner and repo:
        if secret_exists(repo_path, secret_name, github_handle):
            gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].delete()
            if gh_status == 204:
                status = True
            else:
                logger.error(f"Error removing secret {repo_path} : {gh_status}")
        else:
            status = True  # Treat as if it was a removal if secret does not exist
    else:
        logger.error(f"Unable to determine owner and repo from {repo_path}")
    return status


def main():
    description = "Synchronize secrets with github repos\n"
    parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--secrets-file", help="Secrets file", dest="secrets_filename", required=True
    )
    parser.add_argument(
        "--github-pat", help="Github access token", dest="github_pat", required=True
    )
    parser.add_argument(
        "--verbose", help="Turn on DEBUG logger", action="store_true", required=False
    )
    parser.add_argument(
        "--dryrun",
        help="Do a dryrun - no changes will be performed",
        dest="dryrun",
        action="store_true",
        default=False,
        required=False,
    )
    args = parser.parse_args()
    log_level = "INFO"
    if args.verbose:
        log_level = "TRACE"
    logger.remove()
    logger.add(
        sink=sys.stderr, colorize=True, format="<level>{message}</level>", level=log_level,
    )
    # if set, make no changes and log only what would happen
    dryrun = args.dryrun
    # Read the yaml file
    secrets = read_secrets_file(args.secrets_filename)
    logger.debug(pformat(secrets))
    # Initialize connection to Github API
    github_handle = GitHub(token=args.github_pat)
    # Loop over every entry in the config
    # For each entry, get the public key for the repo and encrypt the secret
    # Write the secret
    for secret in secrets["secrets"]:
        remove = False
        repos = []
        if secret and "name" in secret:
            secret_name = secret["name"].strip()
            logger.info("Secret found: %s" % secret_name)
        if "value" in secret and secret["value"]:
            secret_val = secret["value"]
        else:
            # We assume if there is no value, we are removing the secret
            logger.info(f"No value defined for {secret_name} - removing parameter from all repos")
            remove = True
        if "groups" in secret:
            for group in secret["groups"]:
                if group in secrets["groups"]:
                    repos.extend(secrets["groups"][group])
                else:
                    logger.info("No group defined for %s" % group)
        if "repos" in secret:
            repos.extend(secret["repos"])
        if repos:
            for repo in repos:
                repo = repo.strip()
                if remove:
                    if dryrun:
                        logger.info(f"DRYRUN: Removing {secret_name} from {repo}")
                    else:
                        if remove_secret(repo, secret_name, github_handle):
                            logger.success(f"Successfully removed secret {secret_name} from {repo}")
                        else:
                            logger.error(f"Unable to remove secret {secret_name} from {repo}")
                else:
                    if dryrun:
                        logger.info(f"DRYRUN: Adding {secret_name} to {repo}")
                    else:
                        if upsert_secret(repo, secret_name, secret_val, github_handle):
                            logger.success(
                                f"Successfully added/updated secret {secret_name} in repo {repo}"
                            )
                        else:
                            logger.error(
                                f"Unable to add/update secret {secret_name} in repo {repo}"
                            )
        else:
            logger.error("No name for secret - unable to manage")
    logger.success("Complete")


if __name__ == "__main__":
    main()

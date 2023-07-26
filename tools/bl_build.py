#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import secrets

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def generate_secrets():
    # Generate AES-128 secret keys and IVs
    aes_key1 = secrets.token_bytes(16)
    aes_key2 = secrets.token_bytes(16)
    aes_iv1 = secrets.token_bytes(16)
    aes_iv2 = secrets.token_bytes(16)

    # Write the secret keys and IVs to the output file
    with open("secret_build_output.txt", "w") as file:
        file.write(f"AES Key 1: {aes_key1.hex()}\n")
        file.write(f"AES Key 2: {aes_key2.hex()}\n")
        file.write(f"AES IV 1: {aes_iv1.hex()}\n")
        file.write(f"AES IV 1: {aes_iv2.hex()}\n")


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader(secret1, secret2, iv1, iv2) -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    # Running the make command with the provided secrets as command-line arguments
    make_cmd = f"make SECRET_KEY_1={secret1} SECRET_KEY_2={secret2} IV_1={iv1} IV_2={iv2}"
    subprocess.call("make clean", shell=True)
    status = subprocess.call(make_cmd, shell=True)

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    generate_secrets()

    # Read secrets from the output file
    with open("secret_build_output.txt", "r") as file:
        lines = file.readlines()
        secret1 = lines[0].split(":")[1].strip()
        secret2 = lines[1].split(":")[1].strip()
        iv1 = lines[2].split(":")[1].strip()
        iv2 = lines[3].split(":")[1].strip()

    copy_initial_firmware(firmware_path)
    # Building the bootloader with the secrets as command-line arguments
    if make_bootloader(secret1, secret2, iv1, iv2):
        print("Bootloader built successfully.")
    else:
        print("Bootloader build failed.")
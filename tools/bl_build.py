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
    aes_key = secrets.token_bytes(16)
    aes_iv = secrets.token_bytes(16)
    hmac_key = secrets.token_bytes(32)
    # ecc_key = secrets.token_bytes(32)

    # Write the secret keys and IVs to the output file
    with open("secret_build_output.txt", "wb") as file:
        file.write(aes_key + b"\n")
        file.write(aes_iv + b"\n")
        file.write(hmac_key + b"\n")
        # file.write(ecc_key + b"\n")
        
    with open(os.path.join(REPO_ROOT, "bootloader/src/skeys.h"), "w") as f:
        f.write("#ifndef SKEYS_H")
        f.write("\n")
        f.write("#define SKEYS_H")
        f.write("\n")
        f.write("const uint8_t IV[16] = {")
        for i in range (15):
            f.write(hex(aes_iv[i]))
            f.write(", ")
        f.write(hex(aes_iv[15]))
        f.write("};")
        f.write("\n")
        f.write("const uint8_t KEY[16] = {")
        for i in range (15):
            f.write(hex(aes_key[i]))
            f.write(", ")
        f.write(hex(aes_key[15]))
        f.write("};")
        f.write("\n")
        f.write("#endif")
        f.close()


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader(aes, iv, hmac) -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    # Running the make command with the provided secrets as command-line arguments
    make_cmd = f"make AES_KEY={aes} IV={iv} HMAC_KEY={hmac}"
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
    with open("secret_build_output.txt", "rb") as file:
        lines = file.readlines()
        aes_key = lines[0].strip()
        iv = lines[1].strip()
        hmac = lines[2].strip()

    copy_initial_firmware(firmware_path)
    # Building the bootloader with the secrets as command-line arguments
    if make_bootloader(aes_key, iv, hmac):
        print("Bootloader built successfully.")
    else:
        print("Bootloader build failed.")
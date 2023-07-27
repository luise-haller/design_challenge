#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
    # Create original hash
    original_sha = SHA256.new(firmware)
    original_hash = original_sha.digest()

    #Load keys from secret_build_output.txt
    with open("secret_build_output.txt", "rb") as file:
        aes_key = file.readline().strip()
        iv = file.readline().strip()
        hmac_key = file.readline().strip()
        
    # Create cipher and hash    
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce = iv)
    cipher.encrypt(firmware)
    encrypted_sha = SHA256.new(firmware)
    encrypted_hash = encrypted_sha.digest()
    
    # Append hashes to firmware
    firmware = firmware + original_hash + encrypted_hash
    
    # Append null-terminated message to end of firmware
    firmware = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_final = metadata + firmware

    # Write final firmware to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_final)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)

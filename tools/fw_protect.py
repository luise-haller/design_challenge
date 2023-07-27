#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        

    #Load keys from secret_build_output.txt
    with open("secret_build_output.txt", "rb") as file:
        aes_key = file.readline().rstrip()
        iv = file.readline().rstrip()
        hmac = file.readline().rstrip()
        
    # Create cipher and hash    
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce = iv)

    enc_firmware, mac = cipher.encrypt_and_digest(firmware)
    
    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Frame includes Metadata, Encrypted Firmware, MAC
    frame = metadata + enc_firmware + mac

    #
    hMAC = HMAC.new(hmac, msg=frame, digestmod=SHA256).digest()

    # Frame + HMAC + Message + Null Byte
    firmware_blob = frame + hMAC + message.encode() + b'\00'


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

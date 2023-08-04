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
from Crypto.Util.Padding import pad


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    #Load keys from secret_build_output.txt
    with open("secret_build_output.txt", "rb") as file:
        aes_key = file.readline().rstrip()
        iv = file.readline().rstrip()
        # hmac = file.readline().rstrip()
        
    # Create cipher   
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)

    # Encrypts firmware 
    enc_firmware = cipher.encrypt(pad(firmware, AES.block_size))
    
    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Frame includes Metadata, Encrypted Firmware, MAC
    frame = metadata + enc_firmware

    # Generates HMAC of the frame
    # hMAC = HMAC.new(hmac, msg=frame, digestmod=SHA256).digest()

    # Frame + HMAC + Message + Null Byte
    firmware_blob = frame + message.encode() + b'\00'

    # Write final firmware to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)

    """# Load firmware bianry from infile
    with open(infile, 'rb') as fp:
        firmware_final = fp.read()

    # Extract metadata, og hash, encrypted hash, HMAC tag
    metadata = firmware_final[:4]
    og_hash = firmware_final[-96:-64]
    encrypted_hash = firmware_final[-64:-32]
    hmac_tag = firmware_final[-32:]

    # get firmware data without metadata and appended mes
    firmware = firmware_final[4:-97]

    # Unpack version and size from metadata
    version, size = struct.unpack('<HH', metadata)

    #Load keys from secret_build_output.txt
    with open("secret_build_output.txt", "rb") as file:
        aes_key = file.readline().strip()
        iv = file.readline().strip()
        hmac_key = file.readline().strip()

    # Calculate SHA256 hashes and HMAC tag for received firmware
    recalculated_og_sha = SHA256.new(firmware)
    recalculated_og_hash = recalculated_og_sha.digest()

    # Decrypt firmware using AES-GCM so as to recalculate encrypted SHA256 hash
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    decrypted_firmware = aes_cipher.decrypt(firmware)

    # Recalculate SHA256 hashes and HMAC tag for received firmware
    recalculated_encrypted_sha = SHA256.new(decrypted_firmware)
    recalculated_encrypted_hash = recalculated_encrypted_sha.digest()

    # Recalculate HMAC tag
    hmac_generate = HMAC.new(hmac_key, msg=decrypted_firmware, digestmod=SHA256)
    recalculated_hmac_tag = hmac_generate.digest()"""

    """# compare the calculated values with the extracted ones to verify firmware
    if og_hash == recalculated_og_hash and encrypted_hash == recalculated_encrypted_hash and hmac_tag == recalculated_hmac_tag:
        print("Firmware integrity verified")
    else:
        print("Firmware integrity verfication failed") """

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
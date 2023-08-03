#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time
import socket

from util import *

RESP_OK = b"\x00"
FRAME_SIZE = 256


def send_metadata(ser, metadata, debug=False):

    # Unpacks metadata (first 4 bytes) to extract version and size
    version, size = struct.unpack_from("<HH", metadata)
    # Prints the version and size info extracted from the metadata
    print(f"Version: {version}\nSize: {size} bytes\n")

    # Sends a handshake "U" to initiate the update process
    ser.write(b"U")

    # Wait for the bootloader to enter update mode by receiving "U"
    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte") 
        pass

    # Sends the metadata to bootlodaer
    if debug:
        print(metadata)

    ser.write(metadata)

    # Wait for a response (OK) from the bootloader to confirm successful receipt of the metadata
    resp = ser.read(1)
    # Check if response from bootloader is not as expected
    # If not, raises a RuntimeError
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame to serial port

    # If debug mode is enabled, print the hexadecimal representation of the frame
    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for a response (OK) from the bootloader

    time.sleep(0.1) # Introduce a small delay to allow the bootloader to process the frame

    # Check if the response from the bootloader is not the expected RESP_OK
    # If not, raises a RuntimeError
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    # If debug mode is enabled, print the ASCII value of the response
    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    # reads its content into firmware_blob
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    # Extract first 4 bytes of the firmware_blob as metadata and the rest as the firmware data
    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:]

    # Send metadata to the serial port (ser)
    send_metadata(ser, metadata, debug=debug)

    # Loop through the firmware data, diving it into frames and sending each frame to the serial port
    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        # Extract chunk of data from firmware data
        data = firmware[frame_start : frame_start + FRAME_SIZE]

        # Get length of data and construct the frame format
        length = len(data)
        frame_fmt = ">H{}s".format(length)

        # Pack the length and data into a binary frame 
        frame = struct.pack(frame_fmt, length, data)

        # Send frame to serial port
        send_frame(ser, frame, debug=debug)
        # Print a message indicating that the frame has been written
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    # Print message indicating that the firmware writing process is done
    print("Done writing firmware.")

    # Send a zero-length payload to the bootlader to signal the completion of writing the firmware page
    ser.write(struct.pack(">H", 0x0000))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    # If the response (OK) is not as expected, raise a RuntimeError
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    # Print message indicating that the zero-length frame has been written
    print(f"Wrote zero length frame (2 bytes)")

    # Return the updated serial port object
    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    uart0_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart0_sock.connect(UART0_PATH)

    time.sleep(0.2)  # QEMU takes a moment to open the next socket

    uart1_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart1_sock.connect(UART1_PATH)
    uart1 = DomainSocketSerial(uart1_sock)

    time.sleep(0.2)

    uart2_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart2_sock.connect(UART2_PATH)

    # Close unused UARTs (if we leave these open it will hang)
    uart2_sock.close()
    uart0_sock.close()

    update(ser=uart1, infile=args.firmware, debug=args.debug)

    uart1_sock.close()

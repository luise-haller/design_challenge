// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Library Imports
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <beaverssl.h>

// Application Imports
#include "uart.h"

#include "skeys.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware();
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);
void decrypt_firmware(const uint8_t* aes_key, const uint8_t* iv);
void write_decrypt(char* decrypted_data, int decrypted_data_size);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len);

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Encrypted Firmware Buffer and size of encrypted firmware
char data_buffer[32768];
uint16_t encrypted_size;

int main(){
    
    // Copy the secrets from command-line arguments to local variables (arrays)

    // A 'reset' on UART0 will re-start this code at the top of main, won't clear flash, but will clean ram.

    // Initialize UART channels
    // 0: Reset
    // 1: Host Connection
    // 2: Debug
    uart_init(UART0);
    uart_init(UART1);
    uart_init(UART2);

    

    // Enable UART0 interrupt
    IntEnable(INT_UART0);
    IntMasterEnable();

    load_initial_firmware(); // note the short-circuit behavior in this function, it doesn't finish running on reset!

    uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
    uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

    int resp;
    while (1){
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        nl(UART2);
        if (instruction == UPDATE){
            uart_write_str(UART1, "U"); 
            uart_write_str(UART2, "Updating..."); 
            load_firmware();
            uart_write_str(UART2, "Loaded new firmware.\n");
            nl(UART2);
            // Call decrypt_firmware() and pass in the AES key and IV
            decrypt_firmware(KEY, IV);
        } else if (instruction == BOOT){
            uart_write_str(UART1, "Booting...");
            boot_firmware();
        }
    }
    return 0;
}



/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void){

    if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF){
        /*
         * Default Flash startup state is all FF since. Only load initial
         * firmware when metadata page is all FF. Thus, exit if there has
         * been a reset!
         */
        return;
    }

    // Create buffers for saving the release message
    uint8_t temp_buf[FLASH_PAGESIZE];
    char initial_msg[] = "This is the initial release message.";
    uint16_t msg_len = strlen(initial_msg) + 1;
    uint16_t rem_msg_bytes;

    // Get included initial firmware
    int size = (int)&_binary_firmware_bin_size;
    uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;

    // Set version 2 and install
    uint16_t version = 2;
    uint32_t metadata = (((uint16_t)size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    int i;

    for (i = 0; i < size / FLASH_PAGESIZE; i++){
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
    }

    /* At end of firmware. Since the last page may be incomplete, we copy the initial
     * release message into the unused space in the last page. If the firmware fully
     * uses the last page, the release message simply is written to a new page.
     */

    uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
    if (rem_fw_bytes == 0){
        // No firmware left. Just write the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
    } else {
        // Some firmware left. Determine how many bytes of release message can fit
        if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes)){
            rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
        }else{
            rem_msg_bytes = 0;
        }

        // Copy rest of firmware
        memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
        // Copy what will fit of the release message
        memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
        // Program the final firmware and first part of the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

        // If there are more bytes, program them directly from the release message string
        if (rem_msg_bytes > 0){
            // Writing to a new page. Increment pointer
            i++;
            program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
        }
    }
}

/*
 * Load the encrypted firmware into a buffer where it is stored and later decrypted
 */
void load_firmware(){
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_counter = 0;
    uint32_t version = 0;
    uint32_t size = 0;

    // Get version as 16 bytes 
    rcv = uart_read(UART1, BLOCKING, &read);
    version = (uint32_t)rcv;
    rcv = uart_read(UART1, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;

    uart_write_str(UART2, "Received Firmware Version: ");
    uart_write_hex(UART2, version);
    nl(UART2);

    // Get size as 16 bytes 
    rcv = uart_read(UART1, BLOCKING, &read);
    size = (uint16_t)rcv;
    rcv = uart_read(UART1, BLOCKING, &read);
    size |= (uint16_t)rcv << 8;
    encrypted_size = size;

    uart_write_str(UART2, "Received Firmware Size: ");
    uart_write_hex(UART2, size);
    nl(UART2);

    // Compare to old version and abort if older (note special case for version 0).
    uint16_t old_version = *fw_version_address;

    if (version != 0 && version < old_version){
        uart_write(UART1, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    }

    if (version == 0){
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);
    uart_write_str(UART2, "Metadata loaded");
    nl(UART2);

    uart_write(UART1, OK); // Acknowledge the metadata.

    // Loop until all frames have been received and data has successfully been stored
    while (1){

        // Get two bytes for the length.
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length += (int)rcv;

        uart_write_str(UART2, "Frame Length read: ");
        uart_write_hex(UART2, frame_length);
        nl(UART2);

        // Store the frame data into a global buffer
        for (int i = 0; i < frame_length; ++i){
            char new_byte = uart_read(UART1, BLOCKING, &read);
            data_buffer[data_counter] = new_byte;
            data_counter += 1;
        }

        nl(UART2);

        if(frame_length == 0){
                uart_write_str(UART2, "Got zero length frame.\n");
                uart_write(UART1, OK);
                break;
        }

        // If at end of firmware, go to main

        uart_write(UART1, OK); // Acknowledge the frame.
    }                          // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len){
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase(page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE){
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
        if (ret != 0){
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++){
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++){
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, page_addr + num_full_bytes, 4);
    }else{
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, page_addr, data_len);
    }
}

void boot_firmware(void){
    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART2, (char *)fw_release_message_address);

    // Boot the firmware
    __asm(
        "LDR R0,=0x10001\n\t"
        "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';
        
        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}

// Decrypts firmware and uses MAC key to verify the data has not been modified

void decrypt_firmware(const uint8_t* aes_key, const uint8_t* iv) {
    int result;

    // Create new buffer with the AES size
    int padded_size = encrypted_size;
    while (padded_size % 16 > 0) {
        padded_size++;
    }
    char decrypt_buffer[padded_size];
    for (int i = 0; i < padded_size; i++) {
        decrypt_buffer[i] = data_buffer[i];
    }

    // Copy keys over with memcpy
    uint8_t aes_ke[16];
    memcpy(aes_ke, aes_key, 16);
    uint8_t ive[16];
    memcpy(ive, iv, 16);

    // Decrypt the data with AES-CBC mode
    result = aes_decrypt((char*)aes_ke, (char*)ive, decrypt_buffer, padded_size);

    for (int i = 0; i < padded_size; i++) {
        data_buffer[i] = decrypt_buffer[i];
    }

    write_decrypt(data_buffer, encrypted_size);
    
}

// Write decrypted data to flash (in progress)
void write_decrypt(char* decrypted_data, int data_size) {
    uint32_t page_addr = FW_BASE;  
    int data_index = 0; // Index for tracking the current position in the decrypted_data
    int remaining_data = data_size; // Counter for remaining data to be written to flash
    char data_page[FLASH_PAGESIZE]; // Temporary buffer for a single page of flash memory
 
    // Loop until all data is written to flash
    while (remaining_data > 0) {
        // Calculate the number of bytes to write in this iteration (limited by FLASH_PAGESIZE)
        int bytes_to_write = remaining_data > FLASH_PAGESIZE ? FLASH_PAGESIZE : remaining_data;

        // Copy decrypted data to a temporary buffer for Flash programming
        memcpy(data_page, decrypted_data + data_index, bytes_to_write);

        // Try to write flash and check for error
        if (program_flash(page_addr, (unsigned char*)data_page, bytes_to_write) != 0) {
            uart_write(UART1, 0x10);  // Reject the firmware
            SysCtlReset();            // Reset device
            return;
        }

        // Verify flash program by comparing the data_page with the data in flash
        if (memcmp(data_page, (void *) page_addr, bytes_to_write) != 0) {
            uart_write_str(UART2, "Flash check failed.\n"); // Notify UART2 about the failure 
            uart_write(UART1, 0x11);  // Send a rejection signal to the host
            SysCtlReset();            // Reset device to recover from the error
            return;
        }

        // Update variables for the next iteration
        page_addr += FLASH_PAGESIZE; // Move to the next page in flash
        data_index += bytes_to_write; // Move to the next position in the decrypted_data 
        remaining_data -= bytes_to_write; // Decrement the remaining data counter
    }
    uart_write(UART1, OK); // Sends achknowlegment signal to host
}
Pi4 UART AES-192 version
========================

What changed
------------
- Removed the dependency on module_mod.cpp (Pi camera/OpenCV extraction path).
- Added uart_key.c / uart_key.h to receive KEY_HEX from ESP32-CAM over UART.
- Kept the original OpenSSL AES-192-CBC code structure.

Expected ESP32 protocol
----------------------
ESP32 should print lines like:
  READY
  KEY_HEX:<48 hex chars>
  DONE

Pi behavior
-----------
- Waits for READY
- Sends one-byte trigger: G
- Waits for KEY_HEX and DONE
- Uses the received 24-byte key for AES-192-CBC encrypt/decrypt

Build on Pi4
------------
sudo apt update
sudo apt install build-essential libssl-dev
make

Run examples
------------
./aes_uart
./aes_uart /dev/serial0
./aes_uart /dev/ttyUSB0

Wiring
------
Pi TX -> ESP32 RX
Pi RX -> ESP32 TX
Pi GND <-> ESP32 GND
Use 3.3 V UART logic.

If READY keeps repeating
------------------------
That must be fixed on the ESP32 side by printing READY only once per request cycle,
then waiting for 'G', then printing KEY_HEX and DONE, then returning to READY.

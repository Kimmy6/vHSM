# Arduino key control setup

Pi backend now supports:

`KEY_COMMAND:<user>:<encrypt|decrypt>:<1|2|3>`

It forwards the command over serial to Arduino as:

`KEY:<encrypt|decrypt>:<1|2|3>`

## Arduino mapping

- key `1` -> D3 HIGH
- key `2` -> D4 HIGH
- key `3` -> D5 HIGH
- all other mapped pins are set LOW before enabling the selected pin

## On Raspberry Pi

Install pyserial:

```bash
pip install pyserial
```

Optional environment variables:

- `VHSM_ARDUINO_PORT` (default `/dev/ttyACM0`)
- `VHSM_ARDUINO_BAUD` (default `115200`)
- `VHSM_ARDUINO_TIMEOUT` (default `2.0`)

Example:

```bash
export VHSM_ARDUINO_PORT=/dev/ttyACM0
python3 tcp_server.py
```

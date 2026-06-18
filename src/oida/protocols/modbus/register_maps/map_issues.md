# Modbus Register Map Verification Issues

Generated: 2026-03-26

Maps that could not be fully verified against public manufacturer documentation.

## `battery/seplos-bms.json`

Seplos BMS V3 is real and source repos exist, but V3 protocol docs show register ranges at 0x1000+ which differ from the 0-based addresses in this file. May represent V2 protocol or different abstraction layer.

## `evchargers/pcelectric-EV11.3.json`

PC Electric EV11 is a real product and nymea-plugins-modbus source exists, but no official manufacturer Modbus register documentation was found publicly to independently verify register addresses.

## `solar/growatt-inverter.json`

Register addresses 1-7 appear shifted by 2 positions vs official Growatt Modbus RTU Protocol V1.20/V1.24. File maps PV1 voltage at addr 1 but official protocol places it at addr 3 (addrs 1-2 are total input power). Status enum FAULT value is 2 in file but 3 in protocol.

## `solar/solax-sunway.json`

Sunway Solar is a real manufacturer, but support in wills106/homeassistant-solax-modbus is experimental/WIP (not officially listed). Plugin file plugin_sunway.py exists but is not in the supported brands list.

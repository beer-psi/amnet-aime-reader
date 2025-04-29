# amnet-aime-reader

An AMNet-compatible (-ish) AiMe reader emulator.

Requires com2com to map from COM31 to whatever the COM port is for your game. Also disable
AiMe reader emulation in tools.

## Usage

This is compatible(ish) with AMNet - you can add this as an AMNet server, but FeliCa
cards are not accepted.

Alternatively, you can post a MIFARE block 0 dump to `/signin` (either as raw binary
or hex, if hex the `text/plain` content type must be used) to directly card in with
that dump.

## Why?

i wanted to card in bandai namco passports

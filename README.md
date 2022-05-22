# MQTT Vault

A JSON database controlled via MQTT.

## What it Does

MQTT Vault allows you to create virtual IoT devices that retain their state.
These virtual devices communicate over MQTT the same way that many physical IoT devices do, allowing you to control them with the same infrastructure.
SSL certificates are supported for secure connections to the broker.
For details on using the program, please see manpage.md or run **man mqtt_vault** after installing.

## Planned features

The following features are things I plan to add before version 1.0.
These features will increase the security of the program, but are otherwise not necessary.

#### Database encryption - In progress
  - Encrypt the data stored on disk so it can't be accessed without going through MQTT Vault ✅
  - ~~Maybe support using SSL private key as password?~~ Decided against this since certs can get replaced frequently
  - Add a mechanism to change the encryption key
  - Add a mechanism to migrate between encrypted and unencrypted DBs
#### ~~User filter~~ This can't be done since MQTT messages lack sender information.
  - ~~Accept or reject commands based on the MQTT user that sent the message~~
  - ~~Maybe also filter by client ID?~~

## Notes for Contributers

Some of the automated tests require an MQTT broker to be running.
I recommend using mosquitto since this repository contains a test config for mosquitto, but if you want to use another broker I would ask that you add a config file for it so others can use it too.
To make use of the config file, run **mosquitto -c test_data/mosquitto.conf** from the mqtt_vault directory.

All included SSL certificates and private keys use *test* as the password.
If you introduce more certs, please keep using *test* as the password.
The same goes for MQTT user passwords.

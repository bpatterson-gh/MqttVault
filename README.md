<div style="text-align: center;"><img src="mqtt_vault.svg" alt="MQTT Vault logo" width="128"/></div>

# MQTT Vault

A JSON database controlled via MQTT.

## What it Does

MQTT Vault allows you to create virtual IoT devices that retain their state.
These virtual devices communicate over MQTT the same way that many physical IoT devices do, allowing you to control them with the same infrastructure.

For details on using the program, please see manpage.md or run **man mqtt_vault** after installing.

## Features

#### Database
  - Get and set data via MQTT topics
  - Data is stored as individual JSON files
  - Folder structure corresponds to the topic used to set the data

#### MQTT over TLS
  - Optionally encrypts the broker connection using an SSL certificate
  - Supports separate or combined public/private keys

#### Database encryption
  - Optionally encrypts the data stored on disk so it can't be accessed without going through MQTT Vault
  - Allows the encryption key to be changed or removed by passing --change-crypt-key
  - Data is encrypted using the <a href="https://crates.io/crates/chacha20poly1305">chacha20poly1305</a> crate

## Installing

### Arch Linux
MQTT Vault is available on the AUR as `mqtt_vault` or `mqtt_vault-bin`. You can also download the Arch release and extract the files yourself.

### FreeBSD
Download and extract the FreeBSD.tar.gz release.

### Windows
Download and extract the Win64.zip release.

### Build with `cargo`
Run `cargo install mqtt_vault`. Unfortunately, this method does not install the manpage, but you can always grab it from the repo.


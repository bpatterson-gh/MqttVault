% mqtt_vault(1) Version 0.7.0 | MQTT Vault Manual

[!/]: # (This file is used to generate the man page. Compile it with pandoc:)
[/!]: # ( pandoc --standalone -t man manpage.md -o mqtt_vault.1 )

# NAME

MQTT Vault - JSON database controlled via MQTT


# SYNOPSIS

mqtt_vault [*-s config-file*] [*OPTIONS*]


# DESCRIPTION

This program stores and recalls JSON data via MQTT.
It can be used to create virtual IoT devices that retain their state when disconnected.


# OPTIONS

Most options can also be controlled via environment variables.

## -a, \--address  *[string]*

  IP/hostname and port of MQTT broker.

  Default: *tcp://localhost:1883*

  Environment variable: **MQTTV_ADDRESS**

## -c, \--ca-file  *[string]*

  Path to CA file (Secure connections only).

  Default: *none*

  Environment variable: **MQTTV_CAFILE**

## -d, \--db-root  *[string]*

  Path to the database root.

  Default: *db*

  Environment variable: **MQTTV_DBROOT**

## -e, \--cert-file  *[string]*

  Path to client certificate (Secure connections only).

  This may be a combined cert and key, or it may just be the cert.

  Default: *none*

  Environment variable: **MQTTV_CERTFILE**

## -i, \--client-id  *[string]*

  MQTT client ID.

  Default: *random value*

  Environment variable: **MQTTV_CLIENTID**

## -k, \--key-file  *[string]*

  Path to client certificate's private key (Secure connections Only).

  Do not define this field if using a combined cert and key for **\--cert-file**.

  Default: *none*

  Environment variable: **MQTTV_KEYFILE**

## -m, \--max-retries  *[integer]*

  Max number of reconnect attempts to make if the broker connection is lost.

  Values below zero are interpreted as infinite retries.

  Default: *-1*

  Environment variable: **MQTTV_MAXRETRIES**

## -p, \--password  *[string]*

  MQTT user's password.

  Default: *none*

  Environment variable: **MQTTV_PASSWORD**

## -r, \--retry-interval  *[integer]*

  Number of seconds to wait before attempting to reconnect to the broker.

  Default: *30*

  Environment variable: **MQTTV_RETRYINTERVAL**

## -s, \--settings  *[string]*

  Path to configuration file.

  If other command line arguments are included, they will override the configuration file.

  Default: *none*

## -t, \--topic-root  *[string]*

  Root topic that MQTT Vault will use to send & receive messages.

  */get* and */set* will be appended to this.

  Default: *mqtt_vault*

  Environment variable: **MQTTV_TOPICROOT**

## -u, \--user  *[string]*

  MQTT user.

  Default: *none*

  Environment variable: **MQTTV_USER**

## -v, \--mqtt-v5  *[boolean]*

  Connect with MQTT v5.

  Allows response topics to be used when sending a request to the get topic.

  Default: *true*

  Environment variable: **MQTTV_V5**

# EXAMPLES

## Assumptions Used Below

  - **\--db-root** is the *db* directory.

  - **\--topic-root** is *mqtt_vault*, with the full */get* and */set* topics being *mqtt_vault/get* and *mqtt_vault/set*.


## Basics of Topics and Files

  - Data sent to *mqtt_vault/set/data* will be written to *db/data.json*.

  - Data sent to *mqtt_vault/set/data/item* will be written to *db/data/item.json*.

  - Data sent to *mqtt_vault/set/data* will be broadcast to *mqtt_vault/get/data* after it is saved to disk.

  - Querying the */get* topic with an MQTTv5 response topic will cause the value on disk to be read and sent to that response topic.

  - Querying the */get* topic without an MQTTv5 response topic will cause the value on disk to be rebroadcast on the */get* topic.


## Example 1 - /set triggers broadcast to /get

  #. Clients A and B subscribe to *mqtt_vault/get/data*

  #. Client C sends MQTT message *"value"* to *mqtt_vault/set/data*

  #. MQTT Vault creates *db/data.json* with the value *"value"*

  #. MQTT Vault broadcasts *"value"* to *mqtt_vault/get/data*

  #. A and B both receive *"value"* on *mqtt_vault/get/data*


## Example 2 - /get with a response topic

  #. File *db/data.json* contains the value *"value"*

  #. Clients A and B subscribe to *mqtt_vault/get/data*

  #. Client B sends MQTT message *data* to *mqtt_vault/get* with response topic *resp/topic*

  #. MQTT Vault sends the *"value"* from *db/data.json* to *resp/topic*

  #. Client B receives *"value"* on *resp/topic*

  #. Client A receives nothing


## Example 3 - /get without a response topic

  #. File *db/data.json* contains the value *"value"*

  #. Clients A and B subscribe to *mqtt_vault/get/data*

  #. Client B sends MQTT message *data* to *mqtt_vault/get*

  #. MQTT Vault sends the *"value"* from *db/data.json* to *mqtt_vault/get/data*

  #. Clients A and B receive *"value"* on *mqtt_vault/get/data*


# AUTHOR

Bruce Patterson - 
[https://bpatterson.dev](https://bpatterson.dev)

# COPYRIGHT

  ©️ Bruce Patterson 2022

  This program's source code is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with the 
  program, You can obtain one at http://mozilla.org/MPL/2.0/.

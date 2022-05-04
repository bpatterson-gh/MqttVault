//  MQTT Vault - JSON database controlled via MQTT

#[cfg(test)]
mod test {
    use crate::{init_args, process_cli_args, process_env_vars, start_client, Arguments};
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    // Path declarations
    static CONF_PATH_VALID: &str = "test_data/conf/valid.conf";
    static CONF_PATH_PARTIALLY_VALID: &str = "test_data/conf/partially_valid.conf";
    static CONF_PATH_INVALID: &str = "test_data/conf/invalid.conf";

    // Valid config values
    static VALID_CONF_ADDRESS: &str = "ssl://localhost:8884";
    static VALID_CONF_CA_FILE: &str = "test_data/certs/ca.crt";
    static VALID_CONF_CERT_FILE: &str = "test_data/certs/client.crt";
    static VALID_CONF_KEY_FILE: &str = "test_data/certs/client.key";
    static VALID_CONF_USER: &str = "mqtt_vault_ssl_pwd2";
    static VALID_CONF_PASSWORD: &str = "test";
    static VALID_CONF_CLIENT_ID: &str = "test_clId";
    static VALID_CONF_TOPIC_ROOT: &str = "test_topic";
    static VALID_CONF_DB_ROOT: &str = "fake/db";
    static VALID_CONF_MAX_RETRIES: i32 = 2;
    static VALID_CONF_RETRY_INTERVAL: u64 = 10;

    // Initialize test files
    static INIT_FILES: Once = Once::new();
    fn init_files() {
        INIT_FILES.call_once(|| {
            let path = Path::new(CONF_PATH_VALID);
            let parent = path.parent().unwrap_or(path);
            if path != parent {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, conf_file_valid()).unwrap();
            let path = Path::new(CONF_PATH_PARTIALLY_VALID);
            fs::write(path, conf_file_partially_valid()).unwrap();
            let path = Path::new(CONF_PATH_INVALID);
            fs::write(path, conf_file_invalid()).unwrap();
        });
    }

    // Create a config file that should be parsed successfully by Arguments::from_file()
    fn conf_file_valid() -> String {
        let mut s = String::from(std::format!("address =  {} \n", VALID_CONF_ADDRESS));
        s.push_str(&std::format!("ca-file={}\n", VALID_CONF_CA_FILE));
        s.push_str(&std::format!("cert-file ={}\n", VALID_CONF_CERT_FILE));
        s.push_str("# Comment  \n");
        s.push_str(&std::format!("key-file= {}  \n", VALID_CONF_KEY_FILE));
        s.push_str(&std::format!("user = {}\n\n", VALID_CONF_USER));
        s.push_str("// Comment\n");
        s.push_str(&std::format!("password = {} \n", VALID_CONF_PASSWORD));
        s.push_str(&std::format!("client-id= {}\n \n", VALID_CONF_CLIENT_ID));
        s.push_str(&std::format!("topic-root={}\n", VALID_CONF_TOPIC_ROOT));
        s.push_str("Comment\n");
        s.push_str(&std::format!("db-root = {}\n", VALID_CONF_DB_ROOT));
        s.push_str(&std::format!("max-retries = {}\n", VALID_CONF_MAX_RETRIES));
        s.push_str(&std::format!(
            "retry-interval = {}\n",
            VALID_CONF_RETRY_INTERVAL
        ));
        s.push_str("mqtt-v5 = fAlSe \n");
        s
    }

    // Load a valid configuration from a file and verify that it creates an MqttClient successfully
    #[test]
    fn conf_valid() {
        init_files();
        let args = Arguments::from_file(CONF_PATH_VALID);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.mqtt_v5, false);

        let mqtt_client = start_client(args);
        match mqtt_client {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{}", e);
                assert!(false);
            }
        }
    }

    // Create a config file that should be parsed successfully by Arguments::from_file() with some data missing
    fn conf_file_partially_valid() -> String {
        let mut s = String::from(std::format!("address =  {} \n", VALID_CONF_ADDRESS));
        s.push_str(&std::format!("ca file={}\n", VALID_CONF_CA_FILE));
        s.push_str("mqtt-v5 = 0");
        s
    }

    // Load a partially valid configuration from a file
    #[test]
    fn conf_partially_valid() {
        init_files();
        let args = Arguments::from_file(CONF_PATH_PARTIALLY_VALID);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, "");
        assert_eq!(args.mqtt_v5, false);
    }

    // Create a config file that has no parse-able data
    fn conf_file_invalid() -> String {
        let mut s = String::from(std::format!("addres =  irrelevent \n"));
        s.push_str("mqtt-v5 =  \n");
        s
    }

    // Try to load an invalid configuration from a file, and fail
    #[test]
    fn conf_invalid() {
        init_files();
        let args = Arguments::from_file(CONF_PATH_INVALID);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.address, "tcp://localhost:1883");
        assert_eq!(args.mqtt_v5, true);
    }

    // Verify that short command line arguments are applied correctly
    #[test]
    fn env_vars() {
        std::env::set_var("MQTTV_ADDRESS", VALID_CONF_ADDRESS);
        std::env::set_var("MQTTV_CAFILE", VALID_CONF_CA_FILE);
        std::env::set_var("MQTTV_DBROOT", VALID_CONF_DB_ROOT);
        std::env::set_var("MQTTV_CERTFILE", VALID_CONF_CERT_FILE);
        std::env::set_var("MQTTV_CLIENTID", VALID_CONF_CLIENT_ID);
        std::env::set_var("MQTTV_KEYFILE", VALID_CONF_KEY_FILE);
        std::env::set_var("MQTTV_MAXRETRIES", VALID_CONF_MAX_RETRIES.to_string());
        std::env::set_var("MQTTV_PASSWORD", VALID_CONF_PASSWORD);
        std::env::set_var("MQTTV_RETRYINTERVAL", VALID_CONF_RETRY_INTERVAL.to_string());
        std::env::set_var("MQTTV_TOPICROOT", VALID_CONF_TOPIC_ROOT);
        std::env::set_var("MQTTV_USER", VALID_CONF_USER);
        std::env::set_var("MQTTV_V5", "fAlSe");

        let mut args = Arguments::new();
        process_env_vars(std::env::vars(), &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.mqtt_v5, false);
    }

    // Verify that short command line arguments are applied correctly
    #[test]
    fn cli_args_short() {
        let mut cli_args: Vec<String> = Vec::new();
        cli_args.push(String::from("-a"));
        cli_args.push(String::from(VALID_CONF_ADDRESS));
        cli_args.push(String::from("-c"));
        cli_args.push(String::from(VALID_CONF_CA_FILE));
        cli_args.push(String::from("-d"));
        cli_args.push(String::from(VALID_CONF_DB_ROOT));
        cli_args.push(String::from("-e"));
        cli_args.push(String::from(VALID_CONF_CERT_FILE));
        cli_args.push(String::from("-i"));
        cli_args.push(String::from(VALID_CONF_CLIENT_ID));
        cli_args.push(String::from("-k"));
        cli_args.push(String::from(VALID_CONF_KEY_FILE));
        cli_args.push(String::from("-m"));
        cli_args.push(VALID_CONF_MAX_RETRIES.to_string());
        cli_args.push(String::from("-p"));
        cli_args.push(String::from(VALID_CONF_PASSWORD));
        cli_args.push(String::from("-r"));
        cli_args.push(VALID_CONF_RETRY_INTERVAL.to_string());
        cli_args.push(String::from("-t"));
        cli_args.push(String::from(VALID_CONF_TOPIC_ROOT));
        cli_args.push(String::from("-u"));
        cli_args.push(String::from(VALID_CONF_USER));
        cli_args.push(String::from("-v"));
        cli_args.push(String::from("fAlSe"));

        let mut args = Arguments::new();
        process_cli_args(cli_args, &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.mqtt_v5, false);
    }

    // Verify that long command line arguments are applied correctly
    #[test]
    fn cli_args_long() {
        let mut cli_args: Vec<String> = Vec::new();
        cli_args.push(String::from("--address"));
        cli_args.push(String::from(VALID_CONF_ADDRESS));
        cli_args.push(String::from("--ca-file"));
        cli_args.push(String::from(VALID_CONF_CA_FILE));
        cli_args.push(String::from("--db-root"));
        cli_args.push(String::from(VALID_CONF_DB_ROOT));
        cli_args.push(String::from("--cert-file"));
        cli_args.push(String::from(VALID_CONF_CERT_FILE));
        cli_args.push(String::from("--client-id"));
        cli_args.push(String::from(VALID_CONF_CLIENT_ID));
        cli_args.push(String::from("--key-file"));
        cli_args.push(String::from(VALID_CONF_KEY_FILE));
        cli_args.push(String::from("--max-retries"));
        cli_args.push(VALID_CONF_MAX_RETRIES.to_string());
        cli_args.push(String::from("--password"));
        cli_args.push(String::from(VALID_CONF_PASSWORD));
        cli_args.push(String::from("--retry-interval"));
        cli_args.push(VALID_CONF_RETRY_INTERVAL.to_string());
        cli_args.push(String::from("--topic-root"));
        cli_args.push(String::from(VALID_CONF_TOPIC_ROOT));
        cli_args.push(String::from("--user"));
        cli_args.push(String::from(VALID_CONF_USER));
        cli_args.push(String::from("--mqtt-v5"));
        cli_args.push(String::from("0"));

        let mut args = Arguments::new();
        process_cli_args(cli_args, &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.mqtt_v5, false);
    }

    // Verify that command line arguments override arguments from a file
    #[test]
    fn file_and_cli() {
        init_files();
        let args = Arguments::from_file(CONF_PATH_PARTIALLY_VALID);
        assert!(args.is_ok());

        let mut args = args.unwrap();
        let cli_args = vec![String::from("--ca-file"), String::from(VALID_CONF_CA_FILE)];
        process_cli_args(cli_args, &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.mqtt_v5, false);
    }

    // Verify that environment variables override arguments from a file
    #[test]
    fn file_and_env() {
        init_files();
        std::env::set_var("MQTTV_CAFILE", VALID_CONF_CA_FILE);

        let args = init_args();

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.mqtt_v5, false);
    }
}

mod json_helper;
mod mqtt_client;
use mqtt_client::MqttClient;
use paho_mqtt::{SslOptions, SslOptionsBuilder};
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

// Arguments for creating an MqttClient
struct Arguments {
    address: String,
    ca_file: String,
    cert_file: String,
    key_file: String,
    user: String,
    password: String,
    client_id: String,
    topic_root: String,
    db_root: String,
    mqtt_v5: bool,
    max_retries: i32,
    retry_interval: u64,
}

impl Arguments {
    // Create a set of default Arguments
    pub fn new() -> Arguments {
        let client_id = Uuid::new_v4().as_simple().to_string();
        Arguments {
            address: String::from("tcp://localhost:1883"),
            ca_file: String::from(""),
            cert_file: String::from(""),
            key_file: String::from(""),
            user: String::from(""),
            password: String::from(""),
            client_id,
            topic_root: String::from("mqtt_vault"),
            db_root: String::from("db"),
            mqtt_v5: true,
            max_retries: -1,
            retry_interval: 30,
        }
    }

    // Parse keys and values from a file
    fn parse_file(file: &mut File) -> Result<Vec<String>, String> {
        let mut file_str = String::new();
        let res = file.read_to_string(&mut file_str);
        if !res.is_ok() {
            return Err(String::from("Could not read file."));
        }
        let mut vec: Vec<String> = Vec::new();
        for line in file_str.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() == 3 && words[1] == "=" {
                vec.push(String::from(words[0]));
                vec.push(String::from(words[2]));
            } else if words.len() == 1 {
                let words: Vec<&str> = words[0].split("=").collect();
                if words.len() == 2 {
                    vec.push(String::from(words[0]));
                    vec.push(String::from(words[1]));
                }
            } else if words.len() == 2 {
                if &words[0][words[0].len() - 1..] == "=" {
                    vec.push(String::from(&words[0][..words[0].len() - 1]));
                    vec.push(String::from(words[1]));
                } else if &words[1][0..1] == "=" {
                    vec.push(String::from(words[0]));
                    vec.push(String::from(&words[1][1..]));
                }
            }
        }
        Ok(vec)
    }

    // Create Arguments from a config file
    pub fn from_file(file_path: &str) -> Result<Arguments, String> {
        let mut args = Arguments::new();
        let f = File::open(file_path);
        match f {
            Ok(mut file) => {
                let file_args = Arguments::parse_file(&mut file);
                match file_args {
                    Ok(f_args) => {
                        for i in 0..=f_args.len() - 1 {
                            match f_args[i].as_str() {
                                "address" => args.address(&f_args[i + 1]),
                                "ca-file" => args.ca_file(&f_args[i + 1]),
                                "cert-file" => args.cert_file(&f_args[i + 1]),
                                "client-id" => args.client_id(&f_args[i + 1]),
                                "db-root" => args.db_root(&f_args[i + 1]),
                                "key-file" => args.key_file(&f_args[i + 1]),
                                "max-retries" => args.max_retries(&f_args[i + 1]),
                                "mqtt-v5" => match f_args[i + 1].to_lowercase().as_str() {
                                    "0" | "false" => args.mqtt_v5(false),
                                    _ => args.mqtt_v5(true),
                                },
                                "password" => args.password(&f_args[i + 1]),
                                "retry-interval" => args.retry_interval(&f_args[i + 1]),
                                "topic-root" => args.topic_root(&f_args[i + 1]),
                                "user" => args.user(&f_args[i + 1]),
                                _ => &mut args,
                            };
                        }
                    }
                    Err(e_str) => return Err(e_str),
                }
            }
            Err(_) => {
                let mut e_str = String::from("Failed to open ");
                e_str.push_str(file_path);
                return Err(e_str);
            }
        }
        Ok(args)
    }

    pub fn address(&mut self, address: &str) -> &mut Self {
        self.address = String::from(address);
        self
    }
    pub fn ca_file(&mut self, ca_file: &str) -> &mut Self {
        self.ca_file = String::from(ca_file);
        self
    }
    pub fn cert_file(&mut self, cert_file: &str) -> &mut Self {
        self.cert_file = String::from(cert_file);
        self
    }
    pub fn key_file(&mut self, key_file: &str) -> &mut Self {
        self.key_file = String::from(key_file);
        self
    }
    pub fn user(&mut self, user: &str) -> &mut Self {
        self.user = String::from(user);
        self
    }
    pub fn password(&mut self, password: &str) -> &mut Self {
        self.password = String::from(password);
        self
    }
    pub fn client_id(&mut self, client_id: &str) -> &mut Self {
        self.client_id = String::from(client_id);
        self
    }
    pub fn topic_root(&mut self, topic_root: &str) -> &mut Self {
        self.topic_root = String::from(topic_root);
        self
    }
    pub fn db_root(&mut self, db_root: &str) -> &mut Self {
        self.db_root = String::from(db_root);
        self
    }

    pub fn mqtt_v5(&mut self, mqtt_v5: bool) -> &mut Self {
        self.mqtt_v5 = mqtt_v5;
        self
    }

    pub fn max_retries(&mut self, max_retries: &str) -> &mut Self {
        let val = max_retries.parse::<i32>();
        self.max_retries = val.unwrap_or(self.max_retries);
        if self.max_retries < 0 {
            self.max_retries = -1;
        }
        self
    }

    pub fn retry_interval(&mut self, retry_interval: &str) -> &mut Self {
        let val = retry_interval.parse::<u64>();
        self.retry_interval = val.unwrap_or(self.retry_interval);
        if self.retry_interval < 1 {
            self.retry_interval = 1;
        }
        self
    }
}

// Apply environment variables
fn process_env_vars(env_vars: std::env::Vars, args: &mut Arguments) {
    for (key, val) in env_vars {
        match key.as_str() {
            "MQTTV_ADDRESS" => args.address(&val),
            "MQTTV_CAFILE" => args.ca_file(&val),
            "MQTTV_DBROOT" => args.db_root(&val),
            "MQTTV_CERTFILE" => args.cert_file(&val),
            "MQTTV_CLIENTID" => args.client_id(&val),
            "MQTTV_KEYFILE" => args.key_file(&val),
            "MQTTV_MAXRETRIES" => args.max_retries(&val),
            "MQTTV_PASSWORD" => args.password(&val),
            "MQTTV_RETRYINTERVAL" => args.retry_interval(&val),
            "MQTTV_TOPICROOT" => args.topic_root(&val),
            "MQTTV_USER" => args.user(&val),
            "MQTTV_V5" => match val.to_lowercase().as_str() {
                "0" | "false" => args.mqtt_v5(false),
                _ => args.mqtt_v5(true),
            },
            _ => args,
        };
    }
}

// Apply command line arguments
fn process_cli_args(cli_args: Vec<String>, args: &mut Arguments) {
    for i in 0..=cli_args.len() - 1 {
        match cli_args[i].as_str() {
            "-a" | "--address" => args.address(&cli_args[i + 1]),
            "-c" | "--ca-file" => args.ca_file(&cli_args[i + 1]),
            "-d" | "--db-root" => args.db_root(&cli_args[i + 1]),
            "-e" | "--cert-file" => args.cert_file(&cli_args[i + 1]),
            "-i" | "--client-id" => args.client_id(&cli_args[i + 1]),
            "-k" | "--key-file" => args.key_file(&cli_args[i + 1]),
            "-m" | "--max-retries" => args.max_retries(&cli_args[i + 1]),
            "-p" | "--password" => args.password(&cli_args[i + 1]),
            "-r" | "--retry-interval" => args.retry_interval(&cli_args[i + 1]),
            "-t" | "--topic-root" => args.topic_root(&cli_args[i + 1]),
            "-u" | "--user" => args.user(&cli_args[i + 1]),
            "-v" | "--mqtt-v5" => match cli_args[i + 1].to_lowercase().as_str() {
                "0" | "false" => args.mqtt_v5(false),
                _ => args.mqtt_v5(true),
            },
            _ => args,
        };
    }
}

// Initialize args with data from a file, environment variables, and/or command line arguments
fn init_args() -> Arguments {
    let mut args: Option<Arguments> = None;
    let cli_args: Vec<String> = std::env::args().collect();
    for i in 0..=cli_args.len() - 1 {
        if cli_args[i] == "-s" || cli_args[i] == "--settings" {
            match Arguments::from_file(&cli_args[i + 1]) {
                Ok(from_file) => args = Some(from_file),
                Err(e_str) => eprintln!("{}", e_str),
            }
        }
    }
    let mut args = args.unwrap_or(Arguments::new());
    process_env_vars(std::env::vars(), &mut args);
    process_cli_args(cli_args, &mut args);
    args
}

// Create an MqttClient with the given args and verify that it connects
fn start_client(args: Arguments) -> Result<MqttClient, String> {
    let client = MqttClient::new(
        &args.address,
        &args.client_id,
        &args.topic_root,
        &args.db_root,
        args.mqtt_v5,
        args.max_retries,
        args.retry_interval,
    );
    let user = if args.user == "" {
        None
    } else {
        Some(args.user.as_str())
    };
    let password = if args.password == "" {
        None
    } else {
        Some(args.password.as_str())
    };
    let mut ssl_opts: Option<SslOptions> = None;
    if args.cert_file != "" {
        let mut builder = SslOptionsBuilder::new();
        match builder.trust_store(&args.ca_file) {
            Ok(_) => (),
            Err(e) => return Err(std::format!("Bad ca_file ( {} ): {}", args.ca_file, e)),
        }
        match builder.key_store(&args.cert_file) {
            Ok(_) => (),
            Err(e) => return Err(std::format!("Bad cert_file ( {} ): {}", args.cert_file, e)),
        }
        match builder.private_key(&args.key_file) {
            Ok(_) => (),
            Err(e) => return Err(std::format!("Bad key_file ( {} ): {}", args.key_file, e)),
        }
        ssl_opts = Some(builder.finalize());
    }
    match client.connect(user, password, ssl_opts) {
        Ok(_) => (),
        Err(e) => return Err(std::format!("Failed to connect to MQTT broker: {}", e)),
    }
    Ok(client)
}

fn main() {
    let mut client = match start_client(init_args()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    static HALT: AtomicBool = AtomicBool::new(false);
    ctrlc::set_handler(move || {
        HALT.store(true, Ordering::Relaxed);
    })
    .expect("Failed to set handler for termination signals");

    while client.main_loop() {
        if HALT.load(Ordering::Relaxed) {
            return;
        }
    }
}

//  Copyright ©️ Bruce Patterson 2022

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

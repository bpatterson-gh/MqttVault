//  MQTT Vault - JSON database controlled via MQTT

#[cfg(test)]
mod test {
    use crate::mqtt_client::json_helper::JsonHelper;
    use crate::{change_crypt_key, init_args, process_cli_args, process_env_vars, start_client, Arguments};
    use std::fs;
    use std::io::BufRead;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    // Path declarations
    static CONF_PATH_VALID: &str = "test_data/conf/valid.conf";
    static CONF_PATH_PARTIALLY_VALID: &str = "test_data/conf/partially_valid.conf";
    static CONF_PATH_INVALID: &str = "test_data/conf/invalid.conf";
    static CONF_PATH_CHANGE_KEY: &str = "test_data/cck_db";
    static CONF_PATH_CHANGE_KEY_FILE: &str = "test_data/cck_db/test.json";
    static CONF_PATH_CHANGE_KEY_NESTED: &str = "test_data/cck_db/test/nest.json";

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
    static VALID_CONF_FILE_CRYPT_KEY: &str = "s00pers3cure";

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
            let path = Path::new(CONF_PATH_CHANGE_KEY_NESTED);
            let parent = path.parent().unwrap_or(path);
            fs::create_dir_all(parent).unwrap();
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
        s.push_str("file-crypt-key = s00pers3cure \n");
        s.push_str("mqtt-v5 = n \n");
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
        assert_eq!(args.file_crypt_key, VALID_CONF_FILE_CRYPT_KEY);
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
        std::env::set_var("MQTTV_FILECRYPTKEY", VALID_CONF_FILE_CRYPT_KEY);
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
        assert_eq!(args.file_crypt_key, VALID_CONF_FILE_CRYPT_KEY);
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
        cli_args.push(String::from("-f"));
        cli_args.push(String::from(VALID_CONF_FILE_CRYPT_KEY));
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
        cli_args.push(String::from("-v3"));
        cli_args.push(String::from("-v5"));
        cli_args.push(String::from("-S"));
        cli_args.push(String::from("-V"));

        let mut args = Arguments::new();
        process_cli_args(cli_args, &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.file_crypt_key, VALID_CONF_FILE_CRYPT_KEY);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.mqtt_v5, true);
        assert_eq!(args.silent, true);
        assert_eq!(args.verbose, true);
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
        cli_args.push(String::from("--file-crypt-key"));
        cli_args.push(String::from(VALID_CONF_FILE_CRYPT_KEY));
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
        cli_args.push(String::from("-v3"));
        cli_args.push(String::from("--user"));
        cli_args.push(String::from(VALID_CONF_USER));
        cli_args.push(String::from("--silent"));
        cli_args.push(String::from("--verbose"));

        let mut args = Arguments::new();
        process_cli_args(cli_args, &mut args);

        assert_eq!(args.address, VALID_CONF_ADDRESS);
        assert_eq!(args.ca_file, VALID_CONF_CA_FILE);
        assert_eq!(args.db_root, VALID_CONF_DB_ROOT);
        assert_eq!(args.cert_file, VALID_CONF_CERT_FILE);
        assert_eq!(args.file_crypt_key, VALID_CONF_FILE_CRYPT_KEY);
        assert_eq!(args.client_id, VALID_CONF_CLIENT_ID);
        assert_eq!(args.key_file, VALID_CONF_KEY_FILE);
        assert_eq!(args.max_retries, VALID_CONF_MAX_RETRIES);
        assert_eq!(args.password, VALID_CONF_PASSWORD);
        assert_eq!(args.retry_interval, VALID_CONF_RETRY_INTERVAL);
        assert_eq!(args.topic_root, VALID_CONF_TOPIC_ROOT);
        assert_eq!(args.user, VALID_CONF_USER);
        assert_eq!(args.mqtt_v5, false);
        assert_eq!(args.silent, true);
        assert_eq!(args.verbose, true);
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

    // Run change_crypt_key once and check that the data was moved
    fn cck(from_key: &str, to_key: &str) {
        change_crypt_key(PathBuf::from(CONF_PATH_CHANGE_KEY), from_key, to_key);
        let jh = JsonHelper::new(to_key);
        let mut file_path = PathBuf::from(CONF_PATH_CHANGE_KEY_FILE);
        let mut nest_path = PathBuf::from(CONF_PATH_CHANGE_KEY_NESTED);
        if jh.is_encrypted() {
            file_path.set_extension("vault");
            nest_path.set_extension("vault");
        }
        let res = jh.import_json(&file_path);
        if res.is_err() {
            eprintln!("Error importing json: {}", res.err().unwrap());
            assert!(false);
        }
        let res = jh.import_json(&nest_path);
        if res.is_err() {
            eprintln!("Error importing json: {}", res.err().unwrap());
            assert!(false);
        }
    }

    // Verify that files can be encrypted, decrypted, and reencrypted via change_crypt_key
    #[test]
    fn change_crypt_keys() {
        let jh = JsonHelper::new("");
        let file_obj = json::object! {
            "test"   => "42",
        };
        let nest_obj = json::object! {
            "test"   => "nest",
        };
        assert!(jh
            .export_json(&PathBuf::from(CONF_PATH_CHANGE_KEY_FILE), &file_obj)
            .is_ok());
        assert!(jh
            .export_json(&PathBuf::from(CONF_PATH_CHANGE_KEY_NESTED), &nest_obj)
            .is_ok());
        cck("", "key1");
        cck("key1", "key2");
        cck("key2", "");
        assert_eq!(
            jh.import_json(&PathBuf::from(CONF_PATH_CHANGE_KEY_FILE))
                .unwrap(),
            file_obj.dump()
        );
        assert_eq!(
            jh.import_json(&PathBuf::from(CONF_PATH_CHANGE_KEY_NESTED))
                .unwrap(),
            nest_obj.dump()
        );
    }

    // Ensure that the version in Cargo.toml matches the version printed by --version
    #[test]
    fn version_mismatch() {
        let mut test_str = String::from("version = \"");
        test_str.push_str(crate::VERSION);
        test_str.push('"');
        let mut found = false;
        match fs::read("Cargo.toml") {
            Ok(data) => {
                for line in data.lines() {
                    match line {
                        Ok(l) => {
                            if &l == &test_str {
                                found = true;
                            }
                        }
                        Err(_) => (),
                    }
                }
            }
            Err(_) => {
                println!("Failed to open Cargo.toml");
                assert!(false);
            }
        }
        assert_eq!(found, true);
    }
}

mod logger;
mod mqtt_client;
use logger::Logger;
use mqtt_client::json_helper::JsonHelper;
use mqtt_client::MqttClient;
use paho_mqtt::{SslOptions, SslOptionsBuilder};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Error as IoError, Read, Write};
use std::path::PathBuf;
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
    file_crypt_key: String,
    change_crypt_key: bool,
    silent: bool,
    verbose: bool,
    version: bool,
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
            file_crypt_key: String::from(""),
            change_crypt_key: false,
            silent: false,
            verbose: false,
            version: false,
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
                                "file-crypt-key" => args.file_crypt_key(&f_args[i + 1]),
                                "key-file" => args.key_file(&f_args[i + 1]),
                                "max-retries" => args.max_retries(&f_args[i + 1]),
                                "mqtt-v5" => args.mqtt_v5(&f_args[i + 1]),
                                "password" => args.password(&f_args[i + 1]),
                                "retry-interval" => args.retry_interval(&f_args[i + 1]),
                                "topic-root" => args.topic_root(&f_args[i + 1]),
                                "user" => args.user(&f_args[i + 1]),
                                "silent" => args.silent(&f_args[i + 1]),
                                "verbose" => args.verbose(&f_args[i + 1]),
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

    fn str_to_bool(value: &str, default: bool) -> bool {
        match value.to_lowercase().as_str() {
            "0" | "false" | "n" => false,
            "1" | "true" | "y" => true,
            _ => default,
        }
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

    pub fn mqtt_v5(&mut self, mqtt_v5: &str) -> &mut Self {
        self.mqtt_v5 = Arguments::str_to_bool(mqtt_v5, self.mqtt_v5);
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

    pub fn file_crypt_key(&mut self, file_crypt_key: &str) -> &mut Self {
        self.file_crypt_key = String::from(file_crypt_key);
        self
    }

    pub fn change_crypt_key(&mut self) -> &mut Self {
        self.change_crypt_key = true;
        self
    }

    pub fn silent(&mut self, silent: &str) -> &mut Self {
        self.silent = Arguments::str_to_bool(silent, false);
        self
    }

    pub fn verbose(&mut self, verbose: &str) -> &mut Self {
        self.verbose = Arguments::str_to_bool(verbose, false);
        self
    }

    pub fn version(&mut self) -> &mut Self {
        self.version = true;
        self
    }
}

// Get input from STDIN
fn get_input(prompt: &str, show_input: bool) -> String {
    let mut input = String::new();
    if show_input {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        print!("{} ", prompt);
        stdout.flush().unwrap_or(());
        stdin.read_line(&mut input).unwrap_or(0);
        String::from(input.trim_end())
    } else {
        rpassword::prompt_password(prompt).unwrap_or(input)
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
            "MQTTV_FILECRYPTKEY" => args.file_crypt_key(&val),
            "MQTTV_CLIENTID" => args.client_id(&val),
            "MQTTV_KEYFILE" => args.key_file(&val),
            "MQTTV_MAXRETRIES" => args.max_retries(&val),
            "MQTTV_PASSWORD" => args.password(&val),
            "MQTTV_RETRYINTERVAL" => args.retry_interval(&val),
            "MQTTV_TOPICROOT" => args.topic_root(&val),
            "MQTTV_USER" => args.user(&val),
            "MQTTV_V5" => args.mqtt_v5(&val),
            "MQTTV_SILENT" => args.silent(&val),
            "MQTTV_VERBOSE" => args.verbose(&val),
            _ => args,
        };
    }
}

// Apply command line arguments
fn process_cli_args(cli_args: Vec<String>, args: &mut Arguments) {
    for i in 0..=cli_args.len() - 1 {
        let arg_val = if (i + 1) >= cli_args.len() {
            ""
        } else {
            &cli_args[i + 1]
        };
        match cli_args[i].as_str() {
            "-a" | "--address" => args.address(arg_val),
            "-c" | "--ca-file" => args.ca_file(arg_val),
            "-d" | "--db-root" => args.db_root(arg_val),
            "-e" | "--cert-file" => args.cert_file(arg_val),
            "-f" | "--file-crypt-key" => args.file_crypt_key(arg_val),
            "-i" | "--client-id" => args.client_id(arg_val),
            "-k" | "--key-file" => args.key_file(arg_val),
            "-m" | "--max-retries" => args.max_retries(arg_val),
            "-p" | "--password" => args.password(arg_val),
            "-r" | "--retry-interval" => args.retry_interval(arg_val),
            "-t" | "--topic-root" => args.topic_root(arg_val),
            "-u" | "--user" => args.user(arg_val),
            "-S" | "--silent" => args.silent("1"),
            "-V" | "--verbose" => args.verbose("1"),
            "-v3" => args.mqtt_v5("0"),
            "-v5" => args.mqtt_v5("1"),
            "--change-crypt-key" => args.change_crypt_key(),
            "-v" | "--version" => args.version(),
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
    if args.file_crypt_key.to_uppercase() == "STDIN" {
        args.file_crypt_key(&get_input("Enter the encryption key:", false));
    }
    args
}

fn change_crypt_key_recursive(
    current_json: &JsonHelper,
    new_json: &JsonHelper,
    start_path: &PathBuf,
    current_ext: &str,
) -> Result<(), IoError> {
    for entry in std::fs::read_dir(start_path)? {
        let path = entry?.path();
        if path.is_dir() {
            change_crypt_key_recursive(current_json, new_json, &path, current_ext)?;
        // Only attempt to decrypt if path has the correct extension and it isn't already encrypted with the new key
        } else if path.extension().unwrap_or(OsStr::new("")) == current_ext && new_json.import_json(&path).is_err() {
            let mut tmp_path = PathBuf::from(&path);
            tmp_path.set_extension("tmpnew");
            let json_str = current_json.import_json(&path)?;
            match json::parse(&json_str) {
                Ok(data) => new_json.export_json(&tmp_path, &data)?,
                Err(e) => return Err(current_json.json_to_io_error(e, Some(&json_str))),
            }
        }
    }
    Ok(())
}

fn change_crypt_key_success(start_path: &PathBuf, current_ext: &str, new_ext: &str) -> Result<(), IoError> {
    for entry in std::fs::read_dir(start_path)? {
        let path = entry?.path();
        if path.is_dir() {
            change_crypt_key_success(&path, current_ext, new_ext)?;
        } else if path.extension().unwrap_or(OsStr::new("")) == "tmpnew" {
            let mut vault_path = PathBuf::from(&path);
            vault_path.set_extension(current_ext);
            std::fs::remove_file(&vault_path)?;
            vault_path.set_extension(new_ext);
            std::fs::rename(&path, &vault_path)?;
        }
    }
    Ok(())
}

fn change_crypt_key_failure(start_path: &PathBuf) -> Result<(), IoError> {
    for entry in std::fs::read_dir(start_path)? {
        let path = entry?.path();
        if path.is_dir() {
            change_crypt_key_failure(&path)?;
        } else if path.extension().unwrap_or(OsStr::new("")) == "tmpnew" {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn change_crypt_key(db_root: PathBuf, current_key: &str, new_key: &str) {
    let current_json = JsonHelper::new(current_key);
    let new_json = JsonHelper::new(new_key);
    let current_ext = if current_json.is_encrypted() {
        "vault"
    } else {
        "json"
    };
    let new_ext = if new_json.is_encrypted() {
        "vault"
    } else {
        "json"
    };
    match change_crypt_key_recursive(&current_json, &new_json, &db_root, current_ext) {
        Ok(_) => match change_crypt_key_success(&db_root, current_ext, new_ext) {
            Ok(_) => (),
            Err(e) => {
                eprintln!(
                    "Error occurred during cleanup:\n    {}\n\nThe conversion was otherwise successful. \
                You can finish the process manually by renaming any .tmpnew files in your db-root to {}",
                    e, new_ext
                )
            }
        },
        Err(e) => {
            eprintln!(
                "Error:\n    {}\n\nThe conversion was unsuccessful. Your data is still encrypted with the original key.",
                e
            );
            match change_crypt_key_failure(&db_root) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!(
                        "Another error occurred during cleanup:\n    {}\n\n \
                Please remove any lingering .tmpnew files in your db-root before trying to change the key again.",
                        e
                    )
                }
            }
        }
    }
}

fn ask_change_crypt_key(args: &Arguments) {
    let current_key = if args.file_crypt_key == "" {
        get_input(
            "Enter the current encryption key, or leave blank if unencrypted:",
            false,
        )
    } else {
        String::from(&args.file_crypt_key)
    };
    let new_key = get_input(
        "Enter the new encryption key, or leave blank for unencrypted:",
        false,
    );
    if current_key == new_key {
        println!("The current and new keys are the same.");
        return;
    } else if new_key != "" {
        if new_key != get_input("Enter the new encryption key again:", false) {
            println!("The new keys are not the same. Exiting.");
            return;
        }
    }
    print!(
        "You are about to {}. Type YES in all caps to confirm:",
        if new_key == "" {
            "unencrypt your vault"
        } else {
            "change your vault's encryption key"
        }
    );
    if get_input("", true) == "YES" {
        change_crypt_key(PathBuf::from(&args.db_root), &current_key, &new_key);
    } else {
        println!("Not confirmed.");
    }
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
        &args.file_crypt_key,
    )?;
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

// Processes special functions that should not run the main loop
// Returns true if the program should halt instead of starting normally
fn halt_after_special_function(args: &Arguments) -> bool {
    if args.version {
        println!("MQTT Vault version {}", VERSION);
        return true;
    } else if args.change_crypt_key {
        ask_change_crypt_key(&args);
        return true;
    }
    false
}

// Called right before the program terminates
fn on_exit() {
    Logger::log_info("MQTT Halt");
}

const VERSION: &str = "1.0.2";

fn main() {
    let args = init_args();
    if halt_after_special_function(&args) {
        return;
    }

    Logger::init(args.silent, args.verbose);
    let mut client = match start_client(args) {
        Ok(c) => c,
        Err(e) => {
            Logger::log_error(e);
            return;
        }
    };
    static HALT: AtomicBool = AtomicBool::new(false);
    match ctrlc::set_handler(move || {
        on_exit();
        HALT.store(true, Ordering::Relaxed);
    }) {
        Ok(_) => (),
        Err(e) => Logger::log_error(format!(
            "Failed to set handler for termination signals: {}.",
            e
        )),
    }

    while client.main_loop() {
        if HALT.load(Ordering::Relaxed) {
            return;
        }
    }
}

//  Copyright ©️ Bruce Patterson 2022-2024

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

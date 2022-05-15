//  MQTT Vault :: MQTT Client - Paho MQTT client with a JSON database

#[cfg(test)]
mod test {
    use crate::MqttClient;
    use paho_mqtt as mqtt;
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read};
    use std::path::Path;
    use std::sync::Once;
    use std::time::Duration;

    // MqttClient options
    static TCP_ADDR: &str = "tcp://localhost:1883";
    static SSL_ADDR: &str = "ssl://localhost:8883";
    static SSL_PASS_ADDR: &str = "ssl://localhost:8884";
    static NONEXISTENT_ADDR: &str = "tcp://nonexistent:1883";
    static TOPIC_ROOT: &str = "mqttvault";
    static TEST_DB: &str = "test_data/db";

    // Initialize test files
    static INIT_FILES: Once = Once::new();
    fn init_files() {
        INIT_FILES.call_once(|| {
            let path = Path::new(TEST_DB);
            let res = std::fs::remove_dir_all(path);
            assert!(res.is_ok());
        });
    }

    // MQTT SSL options for secure listeners
    pub fn ssl_options() -> mqtt::SslOptions {
        let mut ssl_opts = mqtt::SslOptionsBuilder::new();
        let ssl_opts = ssl_opts.ssl_version(mqtt::SslVersion::Tls_1_2);
        let ssl_opts = ssl_opts.trust_store("test_data/certs/ca.crt");
        assert!(ssl_opts.is_ok());
        let ssl_opts = ssl_opts.unwrap().key_store("test_data/certs/client.crt");
        assert!(ssl_opts.is_ok());
        let ssl_opts = ssl_opts.unwrap().private_key("test_data/certs/client.key");
        assert!(ssl_opts.is_ok());
        ssl_opts.unwrap().finalize()
    }

    // Handle a successful connection
    // Expects an MQTT Broker to be running on localhost:1883
    #[test]
    fn mqtt_connect_success() {
        init_files();
        let cli = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-conn",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = cli.connect(Some("mqtt_connect"), None, None);
        assert!(res.is_ok());
    }

    // Handle a successful SSL connection
    // Expects an MQTT Broker to be running on localhost:8883 using the certs in test_data/certs
    #[test]
    fn mqtt_connect_ssl() {
        init_files();
        let cli = MqttClient::new(
            SSL_ADDR,
            "rusttestcli-conn-ssl",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = cli.connect(Some("mqtt_vault_ssl"), None, Some(ssl_options()));
        assert!(res.is_ok());
    }

    // Handle a successful SSL connection
    // Expects an MQTT Broker to be running on localhost:8884 using the certs in test_data/certs and a password file
    #[test]
    fn mqtt_connect_ssl_password() {
        init_files();
        let cli = MqttClient::new(
            SSL_PASS_ADDR,
            "rusttestcli-conn-ssl-pwd",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = cli.connect(
            Some("mqtt_vault_ssl_pwd"),
            Some("test"),
            Some(ssl_options()),
        );
        assert!(res.is_ok());
    }

    // Handle a failed connection
    #[test]
    fn mqtt_connect_failure() {
        init_files();
        let cli = MqttClient::new(
            NONEXISTENT_ADDR,
            "rusttestfailcli",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = cli.connect(Some("mqtt_noconnect"), None, None);
        assert!(!res.is_ok());
    }

    // Convert topic strings to JSON file paths
    fn topic_to_path(cli: &mut MqttClient, topic_root: &str) {
        let mut topic = String::from(topic_root);
        topic.push_str("/set/topic");
        let path = cli.topic_path(&topic);
        assert!(path.is_ok());
        let path = path.unwrap();
        let mut expected = String::from(&cli.db_root);
        expected.push_str("/topic.json");
        assert_eq!(path.to_str().unwrap_or(""), expected);

        let mut topic = String::from(topic_root);
        topic.push_str("/set/topic/subtopic");
        let path = cli.topic_path(&topic);
        assert!(path.is_ok());
        let path = path.unwrap();
        let mut expected = String::from(&cli.db_root);
        expected.push_str("/topic/subtopic.json");
        assert_eq!(path.to_str().unwrap_or(""), expected);

        let mut topic = String::from(topic_root);
        topic.push_str("/set");
        let path = cli.topic_path(&topic);
        assert!(!path.is_ok());
    }

    // Convert topic strings to JSON file paths with a simple root topic "mqttvault/get" or "mqttvault/set"
    #[test]
    fn topic_to_path_single_root() {
        init_files();
        let mut cli = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-ttp",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        topic_to_path(&mut cli, TOPIC_ROOT);
    }

    // Convert topic strings to JSON file paths with a nested root topic "mqttvault/subtopic/get" or "mqttvault/subtopic/set"
    #[test]
    fn topic_to_path_nested_root() {
        init_files();
        let topic_root = "mqttvault/subtopic";
        let mut cli = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-ttp",
            topic_root,
            TEST_DB,
            true,
            1,
            10,
        );
        topic_to_path(&mut cli, topic_root);
        let topic_root = "mqttvault/subtopic/subsub";
        let mut cli = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-ttp",
            topic_root,
            TEST_DB,
            true,
            1,
            10,
        );
        topic_to_path(&mut cli, topic_root);
    }

    // Update the database on disk for given mqtt topics/payloads
    #[test]
    fn db_updates() {
        init_files();
        let cli = MqttClient::new(TCP_ADDR, "rusttestcli-db", TOPIC_ROOT, TEST_DB, true, 1, 10);
        let res = cli.update_db("mqttvault/set/update_db", "\"nice\"");
        assert!(res.is_ok());

        let res = cli.update_db("mqttvault/set/update_db/subtopic", "\"nice\"");
        assert!(res.is_ok());

        let res = cli.update_db("mqttvault/set", "\"this shouldn't exist\"");
        assert!(!res.is_ok());
    }

    // Paho MQTT client for sending/receiving test messages
    fn create_paho_client(name: &str) -> mqtt::Client {
        let v5_opts = mqtt::CreateOptionsBuilder::new()
            .server_uri(TCP_ADDR)
            .client_id(name)
            .mqtt_version(5)
            .finalize();
        let client = mqtt::Client::new(v5_opts);
        assert!(client.is_ok());
        let client = client.unwrap();
        let mut conn_user = String::from(name);
        conn_user.push_str("-usr");
        let res = client.connect(
            mqtt::ConnectOptionsBuilder::new()
                .user_name(&conn_user)
                .mqtt_version(5)
                .finalize(),
        );
        assert!(res.is_ok());
        client
    }

    // Paho MQTT client for sending/receiving test messages using ssl
    fn create_paho_client_ssl(name: &str) -> mqtt::Client {
        let v5_opts = mqtt::CreateOptionsBuilder::new()
            .server_uri(SSL_ADDR)
            .client_id(name)
            .mqtt_version(5)
            .finalize();
        let client = mqtt::Client::new(v5_opts);
        assert!(client.is_ok());
        let client = client.unwrap();
        let mut conn_user = String::from(name);
        conn_user.push_str("-usr");
        let res = client.connect(
            mqtt::ConnectOptionsBuilder::new()
                .user_name(&conn_user)
                .mqtt_version(5)
                .ssl_options(ssl_options())
                .finalize(),
        );
        assert!(res.is_ok());
        client
    }

    // Utility function to process a single message with an MqttClient
    fn receive_and_process(mqtt_client: &MqttClient) {
        let recv = mqtt_client
            .receiver
            .recv_timeout(mqtt_client.receiver_timeout);
        match recv {
            Ok(option) => match option {
                Some(m) => mqtt_client.process_message(m),
                None => assert!(false),
            },
            Err(_) => assert!(false),
        }
    }

    // Gets the value on disk for a given client and topic
    fn get_file_contents(mqtt_client: &MqttClient, topic: &str) -> Result<String, IoError> {
        let db_path = mqtt_client.topic_path(topic)?;
        match File::open(db_path) {
            Ok(mut file) => {
                let mut ret = String::new();
                file.read_to_string(&mut ret)?;
                Ok(ret)
            }
            Err(e) => Err(e),
        }
    }

    // Sends a payload to the set topic and returns the value written to disk
    fn mqtt_send(
        mqtt_client: &mut MqttClient,
        paho_client: &mut mqtt::Client,
        set_topic: &str,
        payload: &str,
    ) -> Result<String, IoError> {
        let message = mqtt::Message::new(set_topic, payload, 2);
        let res = paho_client.publish(message);
        if !res.is_ok() {
            return Err(IoError::new(IoErrorKind::Other, res.err().unwrap()));
        }
        receive_and_process(mqtt_client);
        get_file_contents(mqtt_client, set_topic)
    }

    // Simulates a simple interaction where a message is sent to the set topic and read from the get topic
    fn mqtt_simple(mqtt_client: &mut MqttClient, paho_client: &mut mqtt::Client) {
        let get_topic = "mqttvault/get/simple";
        let payload = "\"simple_test\"";
        // Subscribe to the get topic
        let res = paho_client.subscribe(get_topic, 1);
        assert!(res.is_ok());
        let paho_recv = paho_client.start_consuming();

        // Send a set message
        let res = mqtt_send(mqtt_client, paho_client, "mqttvault/set/simple", payload);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), payload);

        // Check for a message on the get topic
        let recv = paho_recv.recv_timeout(Duration::from_millis(1000));
        match recv {
            Ok(option) => match option {
                Some(m) => assert!(m.payload_str() == payload),
                None => assert!(false),
            },
            Err(_) => assert!(false),
        }

        // Cleanup
        let res = paho_client.unsubscribe(get_topic);
        assert!(res.is_ok());
    }

    // Simulates a get call with a response topic
    fn mqtt_v5_response(mqtt_client: &mut MqttClient, paho_client: &mut mqtt::Client) {
        let resp_topic = "mqttvault/resp/v5";
        let payload = "\"v5_response_test\"";
        // Subscribe to the response topic
        let res = paho_client.subscribe(resp_topic, 2);
        assert!(res.is_ok());
        let paho_recv = paho_client.start_consuming();

        // Send a set message
        let res = mqtt_send(mqtt_client, paho_client, "mqttvault/set/v5resp", payload);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), payload);

        // Send a get message with a response topic
        let mut props = mqtt::Properties::new();
        let res = props.push_string(mqtt::PropertyCode::ResponseTopic, resp_topic);
        assert!(res.is_ok());
        let message = mqtt::MessageBuilder::new()
            .topic("mqttvault/get")
            .payload("v5resp")
            .qos(2)
            .properties(props)
            .finalize();
        let res = paho_client.publish(message);
        assert!(res.is_ok());
        receive_and_process(mqtt_client);

        // Check for a message on the response topic
        let recv = paho_recv.recv_timeout(Duration::from_millis(1000));
        match recv {
            Ok(option) => match option {
                Some(m) => assert!(m.payload_str() == payload),
                None => assert!(false),
            },
            Err(_) => assert!(false),
        }

        // Cleanup
        let res = paho_client.unsubscribe(resp_topic);
        assert!(res.is_ok());
    }

    // Simulates a get call without a response topic
    fn mqtt_fallback_response(mqtt_client: &mut MqttClient, paho_client: &mut mqtt::Client) {
        let get_topic = "mqttvault/get/fallback";
        let payload = "\"fallback_response_test\"";
        // Send a set message
        let res = mqtt_send(mqtt_client, paho_client, "mqttvault/set/fallback", payload);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), payload);

        // Subscribe to the get topic (This is done after sending the set to avoid getting 2 messages)
        let res = paho_client.subscribe(get_topic, 2);
        assert!(res.is_ok());
        let paho_recv = paho_client.start_consuming();

        // Send a get message without a response topic
        let message = mqtt::Message::new("mqttvault/get", "fallback", 2);
        let res = paho_client.publish(message);
        assert!(res.is_ok());
        receive_and_process(mqtt_client);

        // Check for a message on the get topic
        let recv = paho_recv.recv_timeout(Duration::from_millis(1000));
        match recv {
            Ok(option) => match option {
                Some(m) => assert!(m.payload_str() == payload),
                None => assert!(false),
            },
            Err(_) => assert!(false),
        }

        // Cleanup
        let res = paho_client.unsubscribe(get_topic);
        assert!(res.is_ok());
    }

    // Integration test: process messages and verify the responses
    // Expects an MQTT Broker to be running on localhost:1883
    #[test]
    fn mqtt_messages() {
        init_files();
        let mut mqttvault = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-tester0",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester0"), None, None);
        assert!(res.is_ok());
        let mut paho_client = create_paho_client("mqtt_vault_client_simple");
        mqtt_simple(&mut mqttvault, &mut paho_client);

        let mut mqttvault = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-tester1",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester1"), None, None);
        assert!(res.is_ok());
        let mut paho_client = create_paho_client("mqtt_vault_client_v5resp");
        mqtt_v5_response(&mut mqttvault, &mut paho_client);

        let mut mqttvault = MqttClient::new(
            TCP_ADDR,
            "rusttestcli-tester2",
            TOPIC_ROOT,
            TEST_DB,
            false,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester2"), None, None);
        assert!(res.is_ok());
        let mut paho_client = create_paho_client("mqtt_vault_client_fallback");
        mqtt_fallback_response(&mut mqttvault, &mut paho_client);
    }

    // Integration test: process messages with SSL and verify the responses
    // Expects an MQTT Broker to be running on localhost:8883 using the certs in test_data/certs
    #[test]
    fn mqtt_messages_ssl() {
        init_files();
        let mut mqttvault = MqttClient::new(
            SSL_ADDR,
            "rusttestcli-mqttvault-ssl0",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester_ssl0"), None, Some(ssl_options()));
        assert!(res.is_ok());
        let mut paho_client = create_paho_client_ssl("mqtt_vault_client_ssl_simple");
        mqtt_simple(&mut mqttvault, &mut paho_client);

        let mut mqttvault = MqttClient::new(
            SSL_ADDR,
            "rusttestcli-mqttvault-ssl1",
            TOPIC_ROOT,
            TEST_DB,
            true,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester_ssl1"), None, Some(ssl_options()));
        assert!(res.is_ok());
        let mut paho_client = create_paho_client_ssl("mqtt_vault_client_ssl_v5resp");
        mqtt_v5_response(&mut mqttvault, &mut paho_client);

        let mut mqttvault = MqttClient::new(
            SSL_ADDR,
            "rusttestcli-mqttvault-ssl2",
            TOPIC_ROOT,
            TEST_DB,
            false,
            1,
            10,
        );
        let res = mqttvault.connect(Some("mqtt_vault_tester_ssl2"), None, Some(ssl_options()));
        assert!(res.is_ok());
        let mut paho_client = create_paho_client_ssl("mqtt_vault_client_ssl_fallback");
        mqtt_fallback_response(&mut mqttvault, &mut paho_client);
    }
}

use crate::json_helper::*;
use crossbeam_channel::RecvTimeoutError;
use mqtt::message::Message;
use mqtt::server_response::ServerResponse;
use mqtt::Receiver;
use paho_mqtt as mqtt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct MqttClient {
    client: mqtt::AsyncClient,
    db_root: String,
    receiver: Receiver<Option<Message>>,
    receiver_timeout: Duration,
    retry_attempts: i32,
    retry_attempts_max: i32,
    retry_cooldown: u64,
    retry_instant: Option<Instant>,
    topic_get: String,
    topic_set: String,
    topic_sections: usize,
    v5: bool,
}

impl MqttClient {
    // Construct an MqttClient
    pub fn new(
        server_uri: &str,
        client_id: &str,
        topic_root: &str,
        db_root: &str,
        attempt_v5: bool,
        retry_attempts_max: i32,
        retry_cooldown: u64,
    ) -> MqttClient {
        let (client, v5) = MqttClient::mqtt_create(server_uri, client_id, attempt_v5);
        let recv = client.start_consuming();
        let mut get = String::from(topic_root);
        get.push_str("/get");
        let mut set = String::from(topic_root);
        set.push_str("/set");
        MqttClient {
            client,
            db_root: String::from(db_root),
            receiver: recv,
            receiver_timeout: Duration::from_millis(250),
            retry_attempts: 0,
            retry_attempts_max,
            retry_cooldown,
            retry_instant: None,
            topic_get: get,
            topic_set: set,
            topic_sections: topic_root.split('/').count() + 1,
            v5,
        }
    }

    // Create a paho AsyncClient and set the MQTT version
    fn mqtt_create(
        server_uri: &str,
        client_id: &str,
        attempt_v5: bool,
    ) -> (mqtt::AsyncClient, bool) {
        if attempt_v5 {
            let v5_opts = mqtt::CreateOptionsBuilder::new()
                .server_uri(server_uri)
                .client_id(client_id)
                .mqtt_version(5);
            match mqtt::AsyncClient::new(v5_opts.finalize()) {
                Ok(client) => {
                    return (client, true);
                }
                Err(_) => (),
            }
        }
        let opts = mqtt::CreateOptionsBuilder::new()
            .server_uri(server_uri)
            .client_id(client_id);
        let client = mqtt::AsyncClient::new(opts.finalize()).expect("Failed to create paho client");
        (client, false)
    }

    // Connect to an MQTT broker and subscribe to topic_set & topic_get
    pub fn connect<'a>(
        &self,
        user: Option<&'a str>,
        password: Option<&'a str>,
        ssl_opts: Option<mqtt::SslOptions>,
    ) -> Result<ServerResponse, mqtt::Error> {
        let connect_opts = match ssl_opts {
            Some(opts) => mqtt::ConnectOptionsBuilder::new()
                .mqtt_version(if self.v5 { 5 } else { 0 })
                .user_name(user.unwrap_or(""))
                .password(password.unwrap_or(""))
                .ssl_options(opts)
                .finalize(),
            None => mqtt::ConnectOptionsBuilder::new()
                .mqtt_version(if self.v5 { 5 } else { 0 })
                .user_name(user.unwrap_or(""))
                .password(password.unwrap_or(""))
                .finalize(),
        };
        let token = self.client.connect(connect_opts);
        token.wait()?;
        let mut topic_set = String::from(&self.topic_set);
        topic_set.push_str("/#");
        let token = self.client.subscribe(&topic_set, 1);
        token.wait()?;
        let token = self.client.subscribe(&self.topic_get, 1);
        token.wait()
    }

    // Convert an MQTT topic to a JSON file path
    fn topic_path(&self, topic: &str) -> Result<PathBuf, IoError> {
        if topic == &self.topic_set {
            return Err(IoError::new(
                IoErrorKind::Other,
                format!("Attempted to use {} without a subtopic.", self.topic_set),
            ));
        } else if topic == &self.topic_get {
            return Err(IoError::new(
                IoErrorKind::Other,
                format!("Attempted to use {} without a subtopic.", self.topic_get),
            ));
        }
        let v: Vec<&str> = topic.split('/').collect();
        let mut file = String::from(&self.db_root);
        file.push('/');
        for i in self.topic_sections..v.len() - 1 {
            file.push_str(v[i]);
            file.push('/');
        }
        file.push_str(v[v.len() - 1]);
        file.push_str(".json");
        Ok(PathBuf::from(&file))
    }

    // Create or update a JSON file with an MQTT payload
    fn update_db(&self, topic: &str, payload: &str) -> Result<(), IoError> {
        match json::parse(payload) {
            Ok(json_payload) => match self.topic_path(topic) {
                Ok(path) => export_json(path, json_payload),
                Err(e) => Err(e),
            },
            Err(e) => Err(json_to_io_error(e, Some(payload))),
        }
    }

    // Send a message to topic_get after topic_set is updated
    fn send_update_message(&self, topic: &str, payload: &str) -> Result<(), mqtt::Error> {
        let mut topic_str = String::from(&self.topic_get);
        topic_str.push_str(&topic[self.topic_set.len()..]);
        let message = Message::new_retained(&topic_str, payload, 1);
        self.client.publish(message).wait()
    }

    // Process an MQTT message sent to topic_set
    fn process_set(&self, topic: &str, payload: &str) {
        match self.update_db(topic, payload) {
            Ok(_) => match self.send_update_message(topic, payload) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to send update message for {}: {}", topic, e),
            },
            Err(e) => eprintln!("Failed to update database for {}: {}", topic, e),
        }
    }

    // Send an MQTT v5 response when topic_get is queried
    // Since the sender is expecting a response, one will be sent even if errors occur
    fn send_v5_get_response(&self, topic: &str, resp_topic: &str) {
        let message: Message;
        match self.topic_path(topic) {
            Ok(payload_path) => match import_json(payload_path) {
                Ok(payload) => message = Message::new(resp_topic, payload, 1),
                Err(e) => {
                    eprintln!("Error while preparing v5 response: {}", e);
                    message = Message::new(resp_topic, "", 1)
                }
            },
            Err(e) => {
                eprintln!("Error while preparing v5 response: {}", e);
                message = Message::new(resp_topic, "", 1)
            }
        }
        match self.client.publish(message).wait() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to send v5 response message: {}", e);
            }
        }
    }

    // Send a response to all subscribers when topic_get is queried
    // Ideally, the MQTT v5 response topic should be used instead
    fn send_fallback_get_response(&self, topic: &str) {
        println!("Sending fallback get for {}", topic);
        let mut payload: Option<String> = None;
        match self.topic_path(topic) {
            Ok(path) => match import_json(path) {
                Ok(j) => payload = Some(j),
                Err(e) => eprintln!("Error while preparing fallback response: {}", e),
            },
            Err(e) => eprintln!("Error while preparing fallback response: {}", e),
        }
        match payload {
            None => (),
            Some(payload) => {
                let message = Message::new(topic, payload, 1);
                match self.client.publish(message).wait() {
                    Ok(_) => (),
                    Err(e) => eprintln!("Failed to send fallback response message: {}", e),
                }
            }
        }
    }

    // Process an MQTT message sent to topic_get
    fn process_get(&self, message: Message) {
        let mut get_topic = String::from(message.topic());
        get_topic.push('/');
        get_topic.push_str(&message.payload_str());
        if self.v5 {
            let r_topic = message
                .properties()
                .get_string(mqtt::PropertyCode::ResponseTopic);
            match r_topic {
                Some(resp_topic) => self.send_v5_get_response(&get_topic, &resp_topic),
                None => self.send_fallback_get_response(&get_topic),
            }
        } else {
            self.send_fallback_get_response(&get_topic);
        }
    }

    // Process an incoming MQTT message
    fn process_message(&self, message: Message) {
        let topic = message.topic();
        if topic.len() >= self.topic_set.len() && &topic[..self.topic_set.len()] == &self.topic_set
        {
            self.process_set(topic, &message.payload_str());
        } else if topic.len() >= self.topic_get.len() && &message.topic() == &self.topic_get {
            self.process_get(message);
        }
    }

    // Check for incoming messages and process them
    fn check_messages(&mut self) -> bool {
        let recv = self.receiver.recv_timeout(self.receiver_timeout);
        match recv {
            Ok(option) => match option {
                Some(m) => self.process_message(m),
                None => return false,
            },
            Err(err) => match err {
                RecvTimeoutError::Timeout => (),
                RecvTimeoutError::Disconnected => return false,
            },
        }
        true
    }

    // Process messages and make sure the MQTT connection stays up
    pub fn main_loop(&mut self) -> bool {
        if self.retry_instant.is_some()
            && self.retry_instant.unwrap().elapsed().as_secs() >= self.retry_cooldown
        {
            match self.client.reconnect().wait() {
                Ok(_) => {
                    self.retry_instant = None;
                    self.retry_attempts = 0;
                    println!("Reconnected successfully");
                }
                Err(_) => {
                    println!("Reconnection attempt failed");
                    self.retry_attempts += 1;
                    if self.retry_attempts_max > -1
                        && self.retry_attempts >= self.retry_attempts_max
                    {
                        eprintln!("Failed to reconnect after {} attempts", self.retry_attempts);
                        return false;
                    } else {
                        self.retry_instant = Some(Instant::now());
                        println!("Attempting to reconnect in {} seconds", self.retry_cooldown);
                    }
                }
            }
        } else if self.retry_instant.is_none() && !self.check_messages() {
            if !self.client.is_connected() {
                self.retry_instant = Some(Instant::now());
                println!(
                    "Connection to broker lost\nAttempting to reconnect in {} seconds",
                    self.retry_cooldown
                );
            }
        }
        true
    }
}

//  Copyright ©️ Bruce Patterson 2022

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

//  MQTT Vault :: MQTT Client :: JSON Helper - Utilities for reading and writing JSON files

#[cfg(test)]
mod test {

    use crate::mqtt_client::json_helper::JsonHelper;
    use json::JsonValue;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    // Path declarations
    static JSON_PATH_CORRECT_READ: &str = "test_data/json/read/correct.json";
    static JSON_PATH_CORRECT_WRITE: &str = "test_data/json/write/correct.json";
    static JSON_PATH_CORRUPT: &str = "test_data/json/read/corrupt.json";
    static JSON_PATH_NONEXISTENT: &str = "test_data/json/nonexistent.json";
    static CRYPT_PATH_READ_WRITE: &str = "test_data/json/write/crypt.vault";

    // Create a proper JSON object
    fn json_data_correct() -> JsonValue {
        json::object! {
            "name"   => "value",
        }
    }

    // Create a corrupt JSON string
    fn json_data_corrupt() -> String {
        let jstr = json::object! {
            "name"   => "value",
        }
        .dump();
        String::from(&jstr[0..jstr.len() - 3])
    }

    // Initialize test files
    static INIT_FILES: Once = Once::new();
    fn init_files() {
        INIT_FILES.call_once(|| {
            let path = Path::new(JSON_PATH_CORRECT_READ);
            let parent = path.parent().unwrap_or(path);
            if path != parent {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, json_data_correct().dump()).unwrap();
            let path = Path::new(JSON_PATH_CORRUPT);
            fs::write(path, json_data_corrupt()).unwrap();
            let path = Path::new(CRYPT_PATH_READ_WRITE);
            let parent = path.parent().unwrap_or(&path);
            if path != parent {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, "").unwrap();
        });
    }

    // Reading correctly formatted JSON should return a JsonValue
    #[test]
    fn read_json_correct() {
        init_files();
        let json_helper = JsonHelper::new("");
        let data = json_helper.import_json(&PathBuf::from(JSON_PATH_CORRECT_READ));
        assert!(data.is_ok());
        assert_eq!(data.unwrap(), json::stringify(json_data_correct()));
    }

    // Reading incorrectly formatted JSON should return an Err
    #[test]
    fn read_json_corrupt() {
        init_files();
        let json_helper = JsonHelper::new("");
        let data = json_helper.import_json(&PathBuf::from(JSON_PATH_CORRUPT));
        assert_eq!(data.is_ok(), false);
    }

    // Reading nonexistent JSON files should return an Err
    #[test]
    fn read_json_nonexistent() {
        let json_helper = JsonHelper::new("");
        let data = json_helper.import_json(&PathBuf::from(JSON_PATH_NONEXISTENT));
        assert_eq!(data.is_ok(), false);
    }

    // Writing correctly formatted JSON should succeed
    #[test]
    fn write_json_correct() {
        let json_helper = JsonHelper::new("");
        let res =
            json_helper.export_json(&PathBuf::from(JSON_PATH_CORRECT_WRITE), json_data_correct());
        assert!(res.is_ok());
    }

    // Reading and writing encrypted files should not corrupt the data
    #[test]
    fn read_write_crypt_json() {
        init_files();
        let json_helper = JsonHelper::new("test");
        let res =
            json_helper.export_json(&PathBuf::from(CRYPT_PATH_READ_WRITE), json_data_correct());
        assert!(res.is_ok());
        let data = json_helper.import_json(&PathBuf::from(CRYPT_PATH_READ_WRITE));
        if !data.is_ok() {
            println!("{}", data.err().unwrap());
            assert!(false);
        } else {
            assert_eq!(data.unwrap(), json::stringify(json_data_correct()));
        }
    }
}

mod file_encryption;
use file_encryption::Crypter;
use json::{JsonError, JsonValue};
use std::fs;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::path::PathBuf;

pub struct JsonHelper {
    crypter: Option<Crypter>,
}

impl JsonHelper {
    pub fn new(encryption_key: &str) -> JsonHelper {
        let crypter: Option<Crypter>;
        if encryption_key == "" {
            crypter = None;
        } else {
            crypter = Some(Crypter::new(encryption_key));
        }
        JsonHelper { crypter }
    }

    // Try to import a JsonValue from a file and return the string representation
    pub fn import_json(&self, file: &PathBuf) -> Result<String, IoError> {
        let fdata: String;
        if self.is_encrypted() {
            match fs::read(file) {
                Ok(bdata) => fdata = self.crypter.as_ref().unwrap().decrypt(&bdata),
                Err(e) => {
                    if e.kind() == IoErrorKind::NotFound {
                        fdata = fs::read_to_string(&file)?;
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            fdata = fs::read_to_string(&file)?;
        }
        let jdata = json::parse(&fdata);
        if jdata.is_ok() {
            Ok(json::stringify(jdata.unwrap()))
        } else {
            Err(IoError::new(
                IoErrorKind::Other,
                format!(
                    "JSON file {} is corrupted: {}",
                    file.to_str().unwrap_or("\"\""),
                    &fdata
                ),
            ))
        }
    }

    // Try to write a JsonValue to a file
    // Will not write to disk unless the new value is different
    pub fn export_json(&self, file: &PathBuf, obj: JsonValue) -> Result<(), IoError> {
        let old_val = self.import_json(file).unwrap_or(String::new());
        let new_val = obj.dump();
        if old_val == new_val {
            return Ok(());
        }
        match file.parent() {
            Some(parent) => {
                fs::create_dir_all(parent)?;
                if self.is_encrypted() {
                    fs::write(file, self.crypter.as_ref().unwrap().encrypt(file, &new_val))
                } else {
                    fs::write(file, new_val)
                }
            }
            None => Err(IoError::new(
                IoErrorKind::Other,
                format!(
                    "Could not access parent folder of {}.",
                    file.to_str().unwrap_or("\"\"")
                ),
            )),
        }
    }

    // Convert a JsonError to an IoError
    pub fn json_to_io_error(&self, e: JsonError, json_str: Option<&str>) -> IoError {
        let j = json_str.unwrap_or("");
        match e {
            JsonError::UnexpectedCharacter { ch, .. } => IoError::new(
                IoErrorKind::Other,
                format!("Unexpected character: '{}' in {}", ch, j),
            ),
            JsonError::UnexpectedEndOfJson | JsonError::FailedUtf8Parsing => {
                IoError::new(IoErrorKind::Other, format!("Invalid JSON: {}", j))
            }
            JsonError::ExceededDepthLimit => IoError::new(
                IoErrorKind::Other,
                format!("JSON depth limit exceeded: {}", j),
            ),
            JsonError::WrongType(t) => {
                IoError::new(IoErrorKind::Other, format!("Wrong type: {} in {}", t, j))
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.crypter.is_some()
    }
}

//  Copyright ©️ Bruce Patterson 2022

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

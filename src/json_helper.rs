//  MQTT Vault :: JSON Helper - Utilities for reading and writing JSON files

#[cfg(test)]
mod test {

    use crate::json_helper::{import_json, export_json};
    use json::JsonValue;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    // Path declarations
    static JSON_PATH_CORRECT_READ: &str = "test_data/json/read/correct.json";
    static JSON_PATH_CORRECT_WRITE: &str = "test_data/json/write/correct.json";
    static JSON_PATH_CORRUPT: &str = "test_data/json/read/corrupt.json";
    static JSON_PATH_NONEXISTENT: &str = "test_data/json/nonexistent.json";

    // Create a proper JSON object
    fn json_data_correct() -> JsonValue {
        json::object!{
            "name"   => "value",
        }
    }

    // Create a corrupt JSON string
    fn json_data_corrupt() -> String {
        let jstr = json::object!{
            "name"   => "value",
        }.dump();
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
        });
    }

    // Reading correctly formatted JSON should return a JsonValue
    #[test]
    fn read_json_correct() {
        init_files();
        let data = import_json(PathBuf::from(JSON_PATH_CORRECT_READ));
        assert!(data.is_ok());
        assert_eq!(data.unwrap(), json::stringify(json_data_correct()));
    }

    // Reading incorrectly formatted JSON should return an Err
    #[test]
    fn read_json_corrupt() {
        init_files();
        let data = import_json(PathBuf::from(JSON_PATH_CORRUPT));
        assert_eq!(data.is_ok(), false);
    }

    // Reading nonexistent JSON files should return an Err
    #[test]
    fn read_json_nonexistent() {
        let data = import_json(PathBuf::from(JSON_PATH_NONEXISTENT));
        assert_eq!(data.is_ok(), false);
    }

    // Writing correctly formatted JSON should succeed
    #[test]
    fn write_json_correct() {
        let res = export_json(PathBuf::from(JSON_PATH_CORRECT_WRITE), json_data_correct());
        assert!(res.is_ok());
    }
}

use json::{JsonValue, JsonError};
use std::fs;
use std::path::{PathBuf};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

// Try to import a JsonValue from a file and return the string representation
pub fn import_json(file: PathBuf) -> Result<String, IoError> {
    let fdata = fs::read_to_string(&file)?;
    let jdata = json::parse(&fdata);
    if jdata.is_ok() {
        Ok(json::stringify(jdata.unwrap()))
    } else {
        Err(IoError::new(IoErrorKind::Other, format!("JSON file {} is corrupted.", file.to_str().unwrap_or("\"\""))))
    }
}

// Try to write a JsonValue to a file
pub fn export_json(file: PathBuf, obj: JsonValue) -> Result<(), IoError> {
    match file.parent() {
        Some(parent) => {
            fs::create_dir_all(parent)?;
            fs::write(file, obj.dump())
        },
        None => Err(IoError::new(IoErrorKind::Other, format!("Could not access parent folder of {}.", file.to_str().unwrap_or("\"\"")))),
    }
}

// Convert a JsonError to an IoError
pub fn json_to_io_error(e: JsonError, json_str: Option<&str>) -> IoError {
    let j = json_str.unwrap_or("");
    match e {
        JsonError::UnexpectedCharacter { ch, .. } => IoError::new(IoErrorKind::Other, format!("Unexpected character: '{}' in {}", ch, j)),
        JsonError::UnexpectedEndOfJson |
        JsonError::FailedUtf8Parsing => IoError::new(IoErrorKind::Other, format!("Invalid JSON: {}", j)),
        JsonError::ExceededDepthLimit => IoError::new(IoErrorKind::Other, format!("JSON depth limit exceeded: {}", j)),
        JsonError::WrongType(t) => IoError::new(IoErrorKind::Other, format!("Wrong type: {} in {}", t, j)),
    }
}

//  Copyright ©️ Bruce Patterson 2022

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

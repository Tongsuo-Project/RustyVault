use std::{fmt, time::Duration};

use enum_map::Enum;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use strum::{Display, EnumString};

use crate::errors::RvError;

#[derive(Eq, PartialEq, Copy, Clone, Debug, EnumString, Display, Enum, Serialize, Deserialize)]
pub enum FieldType {
    #[strum(to_string = "string")]
    Str,
    #[strum(to_string = "secret_string")]
    SecretStr,
    #[strum(to_string = "int")]
    Int,
    #[strum(to_string = "bool")]
    Bool,
    #[strum(to_string = "map")]
    Map,
    #[strum(to_string = "array")]
    Array,
    #[strum(to_string = "duration_second")]
    DurationSecond,
    #[strum(to_string = "comma_string_slice")]
    CommaStringSlice,
}

#[derive(Clone)]
pub struct Field {
    pub required: bool,
    pub field_type: FieldType,
    pub default: Value,
    pub description: String,
}

pub trait FieldTrait {
    fn is_int(&self) -> bool;
    fn is_duration(&self) -> bool;
    fn is_comma_string_slice(&self) -> bool;
    fn as_int(&self) -> Option<i64>;
    fn as_duration(&self) -> Option<Duration>;
    fn as_comma_string_slice(&self) -> Option<Vec<String>>;
}

impl FieldTrait for Value {
    fn is_int(&self) -> bool {
        if self.is_i64() {
            return true;
        }

        let int_str = self.as_str();
        if int_str.is_none() {
            return false;
        }

        let int = int_str.unwrap().parse::<i64>().ok();
        if int.is_none() {
            return false;
        }

        true
    }

    fn is_duration(&self) -> bool {
        if self.is_i64() {
            return true;
        }

        let secs_str = self.as_str();
        if secs_str.is_none() {
            return false;
        }

        let secs = secs_str.unwrap().parse::<i64>().ok();
        if secs.is_none() {
            return false;
        }

        true
    }

    fn is_comma_string_slice(&self) -> bool {
        let arr = self.as_array();
        if arr.is_some() {
            let arr_val = arr.unwrap();
            for item in arr_val.iter() {
                let item_val = item.as_str();
                if item_val.is_some() {
                    continue;
                }

                let item_val = item.as_i64();
                if item_val.is_some() {
                    continue;
                }

                return false;
            }

            return true;
        }

        let value = self.as_i64();
        if value.is_some() {
            return true;
        }

        let value = self.as_str();
        if value.is_some() {
            return true;
        }

        false
    }

    fn as_int(&self) -> Option<i64> {
        let mut int = self.as_i64();
        if int.is_none() {
            let int_str = self.as_str();
            if int_str.is_none() {
                return None;
            }

            int = int_str.unwrap().parse::<i64>().ok();
            if int.is_none() {
                return None;
            }
        }

        int
    }

    fn as_duration(&self) -> Option<Duration> {
        let mut secs = self.as_u64();
        if secs.is_none() {
            let secs_str = self.as_str();
            if secs_str.is_none() {
                return None;
            }

            secs = secs_str.unwrap().parse::<u64>().ok();
            if secs.is_none() {
                return None;
            }
        }
        Some(Duration::from_secs(secs.unwrap()))
    }

    fn as_comma_string_slice(&self) -> Option<Vec<String>> {
        let mut ret = Vec::new();
        let arr = self.as_array();
        if arr.is_some() {
            let arr_val = arr.unwrap();
            for item in arr_val.iter() {
                let item_val = item.as_str();
                if item_val.is_some() {
                    ret.push(item_val.unwrap().trim().to_string());
                    continue;
                }

                let item_val = item.as_i64();
                if item_val.is_some() {
                    ret.push(item_val.unwrap().to_string());
                    continue;
                }

                return None;
            }

            return Some(ret);
        }

        let value = self.as_i64();
        if value.is_some() {
            ret.push(value.unwrap().to_string());
            return Some(ret);
        }

        let value = self.as_str();
        if value.is_some() {
            return Some(value.unwrap().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
        }

        None
    }
}

impl Field {
    pub fn new() -> Self {
        Self {
            required: false,
            field_type: FieldType::Str,
            default: json!(null),
            description: String::new(),
        }
    }

    pub fn check_data_type(&self, data: &Value) -> bool {
        match &self.field_type {
            FieldType::SecretStr | FieldType::Str => data.is_string(),
            FieldType::Int => data.is_int(),
            FieldType::Bool => data.is_boolean(),
            FieldType::Array => data.is_array(),
            FieldType::Map => data.is_object(),
            FieldType::DurationSecond => data.is_duration(),
            FieldType::CommaStringSlice => data.is_comma_string_slice(),
        }
    }

    pub fn get_default(&self) -> Result<Value, RvError> {
        if self.default.is_null() {
            match &self.field_type {
                FieldType::SecretStr | FieldType::Str => {
                    return Ok(json!(""));
                },
                FieldType::Int => {
                    return Ok(json!(0));
                },
                FieldType::Bool => {
                    return Ok(json!(false));
                },
                FieldType::Array => {
                    return Ok(json!([]));
                },
                FieldType::Map => {
                    return Ok(serde_json::from_str("{}")?);
                },
                FieldType::DurationSecond => {
                    return Ok(json!(0));
                },
                FieldType::CommaStringSlice => {
                    return Ok(json!([]));
                }
            }
        }

        match &self.field_type {
            FieldType::SecretStr | FieldType::Str => {
                if self.default.is_string() {
                    return Ok(self.default.clone());
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::Int => {
                if self.default.is_i64() {
                    return Ok(self.default.clone());
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::Bool => {
                if self.default.is_boolean() {
                    return Ok(self.default.clone());
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::Array => {
                if self.default.is_array() {
                    return Ok(self.default.clone());
                } else if self.default.is_string() {
                    let arr_str = self.default.as_str();
                    if arr_str.is_none() {
                        return Err(RvError::ErrRustDowncastFailed);
                    }
                    return Ok(serde_json::from_str(arr_str.unwrap())?);
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::Map => {
                if self.default.is_object() {
                    return Ok(self.default.clone());
                } else if self.default.is_string() {
                    let arr_str = self.default.as_str();
                    if arr_str.is_none() {
                        return Err(RvError::ErrRustDowncastFailed);
                    }
                    return Ok(serde_json::from_str(arr_str.unwrap())?);
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::DurationSecond => {
                if self.default.is_duration() {
                    return Ok(self.default.clone());
                }

                return Err(RvError::ErrRustDowncastFailed);
            },
            FieldType::CommaStringSlice => {
                if self.default.is_comma_string_slice() {
                    return Ok(self.default.clone());
                }

                return Err(RvError::ErrRustDowncastFailed);
            }
        }
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("required", &self.required)
            .field("field_type", &self.field_type)
            .field("default", &self.default)
            .field("description", &self.description)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use serde_json::{json, Number, Value};

    use super::*;

    #[test]
    fn test_field_get_default() {
        let mut field = Field::new();
        field.default = json!("foo");
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::String("foo".to_string()));
        field.field_type = FieldType::Int;
        assert!(field.get_default().is_err());
        field.default = json!(443);
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::Number(Number::from(443)));
        field.field_type = FieldType::Bool;
        assert!(field.get_default().is_err());
        field.default = json!(false);
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::Bool(false));
        field.default = json!(true);
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::Bool(true));
        field.field_type = FieldType::Map;
        assert!(field.get_default().is_err());
        let value = json!({
            "type": "int",
            "test": true,
            "num": 999,
            "next": {
                "aa": "bb",
            },
            "arr": [1, 2, 3],
        });
        field.default = value.clone();
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), value);
        field.field_type = FieldType::Array;
        field.default = json!([1, 2, 3]);
        assert!(field.get_default().is_ok());
        let val = json!([1, 2, 3]);
        assert_eq!(field.get_default().unwrap(), val);
        field.field_type = FieldType::DurationSecond;
        field.default = json!("10");
        println!("{:?}", field.get_default());
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap().as_duration().unwrap(), Duration::from_secs(10));
        field.field_type = FieldType::CommaStringSlice;
        field.default = json!([1, 2, 3]);
        assert!(field.get_default().is_ok());
        let val_int = json!([1, 2, 3]);
        let val_str = vec!["1", "2", "3"];
        let val = field.get_default().unwrap();
        assert_eq!(val.as_comma_string_slice(), Some(val_str.iter().map(|&s| s.to_string()).collect::<Vec<String>>()));
        assert_eq!(val, val_int);
        field.default = json!("a,b,c");
        let val_str = vec!["a", "b", "c"];
        let val = field.get_default().unwrap();
        assert_eq!(val.as_comma_string_slice(), Some(val_str.iter().map(|&s| s.to_string()).collect::<Vec<String>>()));
        field.default = json!("a ,, b , c,");
        let val = field.get_default().unwrap();
        assert_eq!(val.as_comma_string_slice(), Some(val_str.iter().map(|&s| s.to_string()).collect::<Vec<String>>()));
    }
}

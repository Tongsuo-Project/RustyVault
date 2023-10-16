use std::fmt;
use std::sync::Arc;
use std::any::Any;
use enum_map::{Enum};
use strum::{Display, EnumString};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::errors::RvError;

#[derive(Eq, PartialEq, Copy, Clone, Debug, EnumString, Display, Enum, Serialize, Deserialize)]
pub enum FieldType {
    #[strum(to_string = "string")]
    Str,
    #[strum(to_string = "int")]
    Int,
    #[strum(to_string = "bool")]
    Bool,
    #[strum(to_string = "map")]
    Map,
}

#[derive(Clone)]
pub struct Field {
    pub field_type: FieldType,
    pub default: Arc<dyn Any + Send + Sync>,
    pub description: String,
}

impl Field {
    pub fn new() -> Self {
        Self {
            field_type: FieldType::Str,
            default: Arc::new(String::new()),
            description: String::new(),
        }
    }

	pub fn get_default(&self) -> Result<Value, RvError> {
        match &self.field_type {
            FieldType::Str => self.cast_value::<String>(),
            FieldType::Int => self.cast_value::<i32>(),
            FieldType::Bool => self.cast_value::<bool>(),
            FieldType::Map => self.cast_value::<Value>(),
        }
    }

    fn cast_value<T: 'static + serde::ser::Serialize>(&self) -> Result<Value, RvError> {
        if let Some(value) = self.default.downcast_ref::<T>() {
            Ok(serde_json::to_value(value).map_err(|_| RvError::ErrRustDowncastFailed)?)
        } else {
            Err(RvError::ErrRustDowncastFailed)
        }
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("field_type", &self.field_type)
            .field("default", &self.default)
            .field("description", &self.description)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use super::*;
    use serde_json::{json, Value, Number};

    #[test]
    fn test_field_get_default() {
        let mut field = Field::new();
        field.default = Arc::new("foo".to_string());
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::String("foo".to_string()));
        field.field_type = FieldType::Int;
        assert!(field.get_default().is_err());
        field.default = Arc::new(443);
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::Number(Number::from(443)));
        field.field_type = FieldType::Bool;
        assert!(field.get_default().is_err());
        field.default = Arc::new(false);
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), Value::Bool(false));
        field.default = Arc::new(true);
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
        field.default = Arc::new(value.clone());
        assert!(field.get_default().is_ok());
        assert_eq!(field.get_default().unwrap(), value);
    }
}

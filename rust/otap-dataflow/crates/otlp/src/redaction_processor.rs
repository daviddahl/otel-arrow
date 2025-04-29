use async_trait::async_trait;
use otap_df_engine::error::Error;
use otap_df_engine::message::Message;
use otap_df_engine::processor::{EffectHandler, Processor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The main config struct for the redaction processor
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct RedactionConfig {
    pub rules: Vec<RedactionRule>,
}

/// One rule (where to apply, and how)
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct RedactionRule {
    /// Dot-separated path in the JSON structure ("user.email", "server.hostname", etc)
    pub path: String,
    pub strategy: RedactionStrategy,
}

/// How to redact: hash, mask, regex replace
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RedactionStrategy {
    Hash {
        #[serde(rename = "hash_type")]
        hash_type: HashType,
        length: Option<u8>,
    },
    Pattern {
        pattern: String,
        replacement: String,
    },
    Mask {
        #[serde(rename = "mask_type")]
        mask_type: MaskType,
        mask_length: Option<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashType {
    Sha256,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::Sha256 => write!(f, "sha256"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "kind", content = "char", rename_all = "snake_case")]
pub enum MaskType {
    Asterisk,        // Mask using *
    X,               // Mask using X
    Custom(char),    // Mask using provided char
}

/// Recursively traverse a serde_json::Value to find a mutable reference to the value at a given dotted path.
/// Returns None if the path doesn't exist.
fn get_value_at_path_mut<'a>(mut value: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let segments = path.split('.');
    for seg in segments {
        value = match value {
            Value::Object(map) => map.get_mut(seg)?,
            _ => return None,
        }
    }
    Some(value)
}

pub struct RedactionProcessor {
    rules: Vec<RedactionRule>,
    hash_cache: HashMap<String, String>,
}

impl RedactionProcessor {
    pub fn new(config: RedactionConfig) -> Self {
        Self {
            rules: config.rules,
            hash_cache: HashMap::new(),
        }
    }

    fn hash_value(&mut self, value: &str, hash_type: &HashType, length: Option<u8>) -> String {
        let key = format!("{}-{}-{:?}", value, hash_type, length);
        if let Some(cached) = self.hash_cache.get(&key) {
            return cached.clone();
        }
        let hash = match hash_type {
            HashType::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(value);
                format!("{:x}", hasher.finalize())
            }
        };
        let result = match length {
            Some(len) => hash.chars().take(len as usize).collect(),
            None => hash,
        };
        // Silence unused result by binding to underscore
        let _ = self.hash_cache.insert(key, result.clone());
        result
    }

    fn apply_redaction(&mut self, value: &mut Value, rule: &RedactionRule) {
        match &rule.strategy {
            RedactionStrategy::Hash { hash_type, length } => {
                if let Some(str_value) = value.as_str() {
                    let hash = self.hash_value(str_value, hash_type, *length);
                    *value = Value::String(hash);
                }
            }
            RedactionStrategy::Pattern { pattern, replacement } => {
                if let Some(str_value) = value.as_str() {
                    match regex::Regex::new(pattern) {
                        Ok(re) => {
                            let result = re.replace(str_value, replacement);
                            *value = Value::String(result.into_owned());
                        }
                        Err(_) => {
                            // Optionally log error: invalid regex, skipping
                            // eprintln!("Invalid regex '{}': {}", pattern, _);
                        }
                    }
                }
            }
            RedactionStrategy::Mask { mask_type, mask_length } => {
                if let Some(str_value) = value.as_str() {
                    // Mask length in number of chars, not bytes!
                    let char_count = str_value.chars().count();
                    let length = mask_length.map(|v| v as usize).unwrap_or(char_count);
                    let mask = match mask_type {
                        MaskType::Asterisk      => "*".repeat(length),
                        MaskType::X             => "X".repeat(length),
                        MaskType::Custom(c)     => c.to_string().repeat(length),
                    };
                    *value = Value::String(mask);
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl Processor for RedactionProcessor {
    type PData = Value;
    async fn process(
        &mut self,
        msg: Message<Self::PData>,
        effect_handler: &mut EffectHandler<Self::PData>,
    ) -> Result<(), Error<Self::PData>> {
        match msg {
            Message::PData(mut data) => {
                let rules = self.rules.clone();
                for rule in &rules {
                    if let Some(target) = get_value_at_path_mut(&mut data, &rule.path) {
                        self.apply_redaction(target, rule);
                    }
                }
                effect_handler.send_message(data).await?;
                Ok(())
            }
            Message::Control(_) => Ok(()),
        }
    }
}

// ------- TESTS & DEMO --------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redaction_hash_mask_pattern() {
        let rules = vec![
            RedactionRule {
                path: "server.hostname".into(),
                strategy: RedactionStrategy::Pattern {
                    pattern: r".*\.([^\.]+)\.foo\.bar\.com$".into(),
                    replacement: "$1".into(),
                },
            },
            RedactionRule {
                path: "user.email".into(),
                strategy: RedactionStrategy::Hash {
                    hash_type: HashType::Sha256,
                    length: Some(8),
                },
            },
            RedactionRule {
                path: "user.password".into(),
                strategy: RedactionStrategy::Mask {
                    mask_type: MaskType::Asterisk,
                    mask_length: Some(8),
                },
            },
        ];
        let config = RedactionConfig { rules: rules.clone() };
        let mut processor = RedactionProcessor::new(config);

        let mut data = json!({
            "server": {
                "hostname": "superhost.cool.foo.bar.com"
            },
            "user": {
                "email": "user@example.com",
                "password": "hunter2"
            }
        });

        // Run the rules as the processor would do
        for rule in &rules {
            if let Some(target) = get_value_at_path_mut(&mut data, &rule.path) {
                processor.apply_redaction(target, rule);
            }
        }

        // "cool"
        assert_eq!(
            data["server"]["hostname"],
            Value::String("cool".to_string())
        );
        // Hashed email, 8 chars hex
        if let Value::String(ref v) = data["user"]["email"] {
            assert_eq!(v.len(), 8);
            // Should look hex-y
            assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
        } else {
            panic!("Not a string");
        }
        // Password masked as exactly 8 '*'
        assert_eq!(
            data["user"]["password"],
            Value::String("********".to_string())
        );
    }

    #[test]
    fn test_mask_custom_char() {
        let rule = RedactionRule {
            path: "foo.bar".to_string(),
            strategy: RedactionStrategy::Mask {
                mask_type: MaskType::Custom('#'),
                mask_length: Some(4),
            },
        };
        let mut config = RedactionConfig { rules: vec![rule.clone()] };
        let mut processor = RedactionProcessor::new(config);
        let mut data = json!({ "foo": { "bar": "123456" } });

        for rule in &[rule] {
            if let Some(target) = get_value_at_path_mut(&mut data, &rule.path) {
                processor.apply_redaction(target, rule);
            }
        }
        assert_eq!(data["foo"]["bar"], Value::String("####".to_string()));
    }

    #[test]
    fn test_path_not_found_no_panic() {
        let rule = RedactionRule {
            path: "foo.unknown".into(),
            strategy: RedactionStrategy::Mask {
                mask_type: MaskType::Asterisk,
                mask_length: Some(4),
            },
        };
        let mut processor = RedactionProcessor::new(RedactionConfig { rules: vec![rule.clone()] });
        let mut data = json!({ "foo": { "bar": "baz" } });

        // Should not panic
        for rule in &[rule] {
            if let Some(target) = get_value_at_path_mut(&mut data, &rule.path) {
                processor.apply_redaction(target, rule);
                panic!("Should not descend into missing path!");
            }
        }
    }
}

/*
YAML config example for reference:
processors:
  redaction:
    type: redaction
    config:
      rules:
        - path: "server.hostname"
          strategy:
            type: pattern
            pattern: ".*\\.([^\\.]+)\\.foo\\.bar\\.com$"
            replacement: "$1"
        - path: "user.email"
          strategy:
            type: hash
            hash_type: "sha256"
            length: 8
        - path: "user.password"
          strategy:
            type: mask
            mask_type: "asterisk"
            mask_length: 8
*/
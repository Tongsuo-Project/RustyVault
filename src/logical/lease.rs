use std::time::{Duration, SystemTime};

use better_default::Default;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, Default, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    #[serde(rename = "lease")]
    pub ttl: Duration,
    #[serde(skip)]
    pub max_ttl: Duration,
    #[default(true)]
    pub renewable: bool,
    #[serde(skip)]
    pub increment: Duration,
    #[serde(skip)]
    #[default(Some(SystemTime::now()))]
    pub issue_time: Option<SystemTime>,
}

impl Lease {
    pub fn new() -> Self {
        Self { ..Default::default() }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn renewable(&self) -> bool {
        return self.renewable;
    }

    pub fn enabled(&self) -> bool {
        self.ttl.as_secs() > 0
    }

    pub fn expiration_time(&self) -> SystemTime {
        if self.issue_time.is_some() {
            self.issue_time.unwrap() + self.ttl
        } else {
            SystemTime::now() + self.ttl
        }
    }
}

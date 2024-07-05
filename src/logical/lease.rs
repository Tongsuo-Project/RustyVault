use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    #[serde(rename = "lease")]
    pub ttl: Duration,
    #[serde(skip)]
    pub max_ttl: Duration,
    pub renewable: bool,
    #[serde(skip)]
    pub increment: Duration,
    #[serde(skip)]
    pub issue_time: Option<SystemTime>,
}

impl Default for Lease {
    fn default() -> Self {
        Self {
            ttl: Duration::new(0, 0),
            max_ttl: Duration::new(0, 0),
            renewable: true,
            increment: Duration::new(0, 0),
            issue_time: Some(SystemTime::now()),
        }
    }
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

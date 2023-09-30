use std::time::{SystemTime, Duration};

pub struct Lease {
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub renewable: bool,
    pub increment: Duration,
    pub issue_time: SystemTime,
}

impl Lease {
    pub fn new() -> Self {
        Self {
            ttl: Duration::new(0, 0),
            max_ttl: Duration::new(0, 0),
            renewable: true,
            increment: Duration::new(0, 0),
            issue_time: SystemTime::now(),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn enabled(&self) -> bool {
        self.ttl.as_secs() > 0
    }

    pub fn expiration_time(&self) -> SystemTime {
        self.issue_time + self.max_ttl
    }
}

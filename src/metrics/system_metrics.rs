use std::sync::{atomic::AtomicU64, Arc, Mutex};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sysinfo::{Disks, Networks, System};
use tokio::time::{self, Duration};

pub struct SystemMetrics {
    system: Arc<Mutex<System>>,
    cpu_usage: Gauge<f64, AtomicU64>,
    total_memory: Gauge<f64, AtomicU64>,
    used_memory: Gauge<f64, AtomicU64>,
    free_memory: Gauge<f64, AtomicU64>,
    total_disk_available: Gauge<f64, AtomicU64>,
    total_disk_space: Gauge<f64, AtomicU64>,
    network_in: Gauge<f64, AtomicU64>,
    network_out: Gauge<f64, AtomicU64>,
    load_avg: Gauge<f64, AtomicU64>,
}

impl SystemMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let cpu_usage = Gauge::<f64, AtomicU64>::default();

        let total_memory = Gauge::<f64, AtomicU64>::default();
        let used_memory = Gauge::<f64, AtomicU64>::default();
        let free_memory = Gauge::<f64, AtomicU64>::default();

        let total_disk_space = Gauge::<f64, AtomicU64>::default();
        let total_disk_available = Gauge::<f64, AtomicU64>::default();

        let network_in = Gauge::<f64, AtomicU64>::default();
        let network_out = Gauge::<f64, AtomicU64>::default();
        let load_avg = Gauge::<f64, AtomicU64>::default();

        registry.register("cpu_usage_percent", "CPU usage percent", cpu_usage.clone());

        registry.register("total_memory", "Total memory", total_memory.clone());
        registry.register("used_memory", "Used memory", used_memory.clone());
        registry.register("free_memory", "Free memory", free_memory.clone());

        registry.register("total_disk_space", "Total disk space", total_disk_space.clone());
        registry.register("total_disk_available", "Total disk available", total_disk_available.clone());

        registry.register("network_in_bytes", "Incoming network traffic in bytes", network_in.clone());
        registry.register("network_out_bytes", "Outgoing network traffic in bytes", network_out.clone());

        registry.register("load_average", "System load average", load_avg.clone());

        let system = Arc::new(Mutex::new(System::new_all()));

        Self { system, cpu_usage, total_memory, used_memory, free_memory, total_disk_available, total_disk_space, network_in, network_out, load_avg }
    }

    pub async fn start_collecting(self: Arc<Self>) {
        let mut interval = time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;
            self.collect_metrics();
        }
    }

    fn collect_metrics(&self) {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_all();

        self.cpu_usage.set(sys.global_cpu_usage() as f64);

        self.total_memory.set(sys.total_memory() as f64);
        self.used_memory.set(sys.used_memory() as f64);
        self.free_memory.set(sys.free_memory() as f64);

        let mut total_available_space = 0;
        let mut total_disk_space = 0;

        for disk in Disks::new_with_refreshed_list().list() {
            total_available_space += disk.available_space();
            total_disk_space += disk.total_space();
        }
        self.total_disk_available.set(total_available_space as f64);
        self.total_disk_space.set(total_disk_space as f64);

        let mut total_network_in = 0;
        let mut total_network_out = 0;

        for (_, n) in Networks::new_with_refreshed_list().list() {
            total_network_in += n.received();
            total_network_out += n.transmitted();
        }

        self.network_in.set(total_network_in as f64);
        self.network_out.set(total_network_out as f64);

        self.load_avg.set(System::load_average().one as f64);
    }
}

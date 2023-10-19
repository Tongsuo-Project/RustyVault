use std::{
	env,
	fs,
    default::Default,
	fs::OpenOptions,
	path::Path,
	collections::HashMap,
	sync::{Arc, RwLock}
};
use daemonize::Daemonize;
use clap::{ArgMatches};
use sysexits::ExitCode;
use actix_web::{
	middleware, web, App, HttpResponse, HttpServer
};
use crate::{
    http,
	errors::RvError,
	EXIT_CODE_OK, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_LOAD_CONFIG_FAILURE,
	storage::{physical, barrier_aes_gcm},
	core::Core
};

pub fn main(config: &str) -> Result<(), RvError> {
	env::set_var("RUST_LOG", "debug");
	env_logger::init();

	let work_dir = "/tmp/rusty_vault/";

    log::info!("config: {}, work_dir: {}", config, work_dir);

	if !Path::new(work_dir).exists() {
        log::info!("create work_dir: {}", work_dir);
		fs::create_dir_all(work_dir)?;
	}

	let dev = true;

	if !dev {
		// start daemon
		let log_path = format!("{}/info.log", work_dir);
		let pid_path = format!("{}/rusty_vault.pid", work_dir);

		let log_file = OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.open(log_path)
			.unwrap();

		let daemonize = Daemonize::new()
			.pid_file(pid_path.clone())
			.chown_pid_file(true)
			.working_directory(work_dir)
			.stdout(log_file.try_clone().unwrap())
			.stderr(log_file)
			.privileged_action(|| log::info!("Start rusty_vault server daemon"));

		match daemonize.start() {
			Ok(_) => {
				let pid = std::fs::read_to_string(pid_path).unwrap();
				log::info!("The rusty_vault server daemon process started successfully, pid is {}", pid);
			}
			Err(e) => log::error!("Error, {}", e),
		}
	}

	let server = actix_rt::System::new();

    let data_dir = work_dir.to_owned() + "rusty_vault_data";
    log::info!("data_dir: {}", data_dir);
	if !Path::new(&data_dir).exists() {
        log::info!("create data_dir: {}", &data_dir);
		fs::create_dir_all(&data_dir)?;
	}

    let mut conf: HashMap<String, String> = HashMap::new();
    conf.insert("path".to_string(), data_dir.to_string());

    let backend = physical::new_backend("file", &conf).unwrap();

    let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

    let core = Arc::new(RwLock::new(Core {
        physical: backend,
        barrier: Arc::new(barrier),
        ..Default::default()
    }));

    {
        let mut c = core.write().unwrap();
        c.self_ref = Some(Arc::clone(&core));
    }

	let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(Arc::clone(&core)))
            .app_data(web::Data::new(Arc::clone(&core)))
            .configure(http::init_service)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .on_connect(http::request_on_connect_handler);

	let addr = "localhost:8099";
    log::info!("start listen, addr: {}", addr);
	http_server = http_server.bind(addr).unwrap();

	log::info!("rusty_vault server starts, waiting for request...");

	server.block_on(async { http_server.run().await })?;
	let _ = server.run();

    Ok(())
}

#[inline]
pub fn execute(matches: &ArgMatches) -> ExitCode {
    if let Some(config_path) = matches.get_one::<String>("config") {
        return (main(&config_path).is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_LOAD_CONFIG_FAILURE);
    }

    return EXIT_CODE_INSUFFICIENT_PARAMS;
}

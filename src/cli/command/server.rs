use std::{
    env,
    fs,
    default::Default,
    fs::OpenOptions,
    path::Path,
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
    cli::config,
    storage::{physical, barrier_aes_gcm},
    core::Core
};

pub const WORK_DIR_PATH_DEFAULT: &str = "/tmp/rusty_vault";

pub fn main(config_path: &str) -> Result<(), RvError> {
    let config = config::load_config(config_path)?;

    if config.storage.len() != 1 {
        return Err(RvError::ErrConfigStorageNotFound);
    }

    if config.listener.len() != 1 {
        return Err(RvError::ErrConfigListenerNotFound);
    }

    env::set_var("RUST_LOG", config.log_level.as_str());
    env_logger::init();

    let (_, storage) = config.storage.iter().next().unwrap();
    let (_, listener) = config.listener.iter().next().unwrap();

    let addr = listener.address.clone();
    log::info!("start listen, addr: {}", addr);

    let mut work_dir = WORK_DIR_PATH_DEFAULT.to_string();
    if !config.work_dir.is_empty() {
        work_dir = config.work_dir.clone();
    }

    if !Path::new(work_dir.as_str()).exists() {
        log::info!("create work_dir: {}", work_dir);
        fs::create_dir_all(work_dir.as_str())?;
    }

    log::info!("config_path: {}, work_dir_path: {}", config_path, work_dir.as_str());

    if config.daemon {
        // start daemon
        let log_path = format!("{}/rusty_vault.log", work_dir);
        let mut pid_path = config.pid_file.clone();
        if !config.pid_file.starts_with("/") {
            pid_path = work_dir.clone() + pid_path.as_str();
        }

        let mut user = "onbody".to_owned();
        if !config.daemon_user.is_empty() {
            user = config.daemon_user.clone();
        }

        let mut group = "onbody".to_owned();
        if !config.daemon_group.is_empty() {
            group = config.daemon_group.clone();
        }

        let log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .truncate(false)
            .open(log_path)
            .unwrap();

        log::debug!("run user: {}, group: {}", user, group);

        let daemonize = Daemonize::new()
            .working_directory(work_dir.as_str())
            .user(user.as_str())
            .group(group.as_str())
            .umask(0o027)
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .pid_file(pid_path.clone())
            .chown_pid_file(true)
            .privileged_action(|| log::info!("Start rusty_vault server daemon"));

        match daemonize.start() {
            Ok(_) => {
                let pid = std::fs::read_to_string(pid_path)?;
                log::info!("The rusty_vault server daemon process started successfully, pid is {}", pid);
            }
            Err(e) => log::error!("Error, {}", e),
        }
    }


    let server = actix_rt::System::new();

    let backend = physical::new_backend(storage.stype.as_str(), &storage.config).unwrap();

    let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

    let core = Arc::new(RwLock::new(Core {
        physical: backend,
        barrier: Arc::new(barrier),
        ..Default::default()
    }));

    {
        let mut c = core.write()?;
        c.config(Arc::clone(&core), Some(config))?;
    }

    let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(Arc::clone(&core)))
            .configure(http::init_service)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .on_connect(http::request_on_connect_handler);

    http_server = http_server.bind(addr)?;

    log::info!("rusty_vault server starts, waiting for request...");

    server.block_on(async { http_server.run().await })?;
    let _ = server.run();

    Ok(())
}

#[inline]
pub fn execute(matches: &ArgMatches) -> ExitCode {
    if let Some(config_path) = matches.get_one::<String>("config") {
        return match main(&config_path) {
            Ok(_) => EXIT_CODE_OK,
            Err(e) => {
                println!("server error: {:?}", e);
                EXIT_CODE_LOAD_CONFIG_FAILURE
            }
        }
    }

    return EXIT_CODE_INSUFFICIENT_PARAMS;
}

use aliddns::{get_global_v4, ifaddrs, Config};
use anyhow::{ensure, Context, Result};
use chrono::Local;
use log::*;
use std::{
    env,
    ffi::OsString,
    fmt::Write,
    fs::File,
    io::Write as IoWrite,
    sync::mpsc::{self, Receiver},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

static LOGGER: Logger = Logger;
static mut LOG_FILE: Option<File> = None;

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = Local::now().format("%F %T");
            // We assure that there's always only one thread mutating LOG_FILE
            match unsafe { LOG_FILE.as_mut() } {
                Some(file) => {
                    // Run as service
                    writeln!(file, "{} [{}] {}", now, record.level(), record.args()).unwrap();
                }
                None => {
                    println!("{} [{}] {}", now, record.level(), record.args());
                }
            }
        }
    }

    fn flush(&self) {}
}

const SERVICE_NAME: &str = "AliDDNS";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// Generate the windows service boilerplate.
// The boilerplate contains the low-level service entry function (ffi_service_main) that parses
// incoming service arguments into Vec<OsString> and passes them to user defined service
// entry (my_service_main).
define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<()> {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);
    if env::args().nth(1).as_deref() == Some("-srv") {
        // Run as service, set current dir to the same as the executable.
        let mut path = env::current_exe().unwrap();
        path.pop();
        env::set_current_dir(&path).unwrap();

        unsafe {
            LOG_FILE = Some(File::create("log.txt").unwrap());
        }

        // Register generated `ffi_service_main` with the system and start the service, blocking
        // this thread until the service is stopped.
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    } else {
        run(None)
    }
}

// Service entry function which is called on background thread by the system with service
// parameters. There is no stdout or stderr at this point so make sure to configure the log
// output to file if needed.
fn my_service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("{:?}", e);
        std::process::exit(1)
    }
}

fn run_service() -> Result<()> {
    info!("Service started");

    // Create a channel to be able to poll a stop event from the service worker loop.
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Tell the system that service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    run(Some(shutdown_rx))?;

    info!("Service stopped");

    // Tell the system that service has stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn run(shutdown_rx: Option<Receiver<()>>) -> Result<()> {
    let config_str = std::fs::read_to_string("config.toml").context("Unable to load config")?;
    let config: Config = toml::from_str(&config_str).context("Unable to parse config")?;

    ensure!(
        config.record_id_v6.is_some() || config.record_id_v4.is_some(),
        "No record ID is available"
    );

    let interval = Duration::from_secs(config.interval_secs);

    loop {
        match update(&config) {
            Ok(addr) if !addr.is_empty() => info!("Update: {}", addr),
            Err(e) => warn!("{:?}", e),
            _ => (),
        }

        match &shutdown_rx {
            Some(rx) => match rx.recv_timeout(interval) {
                // Break the loop either upon stop or channel disconnect
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

                // Continue work if no events were received within the timeout
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            },
            None => std::thread::sleep(interval),
        }
    }
    Ok(())
}

fn update(config: &Config) -> Result<String> {
    let ifs = ifaddrs::list(config.static_v6).context("Unable to list interface")?;
    let interface = ifs.get(0).context("No interface is available")?;
    let mut msg = String::new();
    if let Some(id) = config.record_id_v6 {
        let addr = interface
            .addrs
            .iter()
            .find(|addr| addr.is_ipv6())
            .context("No IPv6 address is available")?;
        if let Err(e) = aliddns::update_record(config, &addr, id) {
            warn!("{:?}", e);
        } else {
            write!(msg, "{}", addr)?;
        }
    }
    if let Some(id) = config.record_id_v4 {
        let global;
        let addr = if config.global_v4 {
            global = get_global_v4().context("Unable to get global IPv4 address")?;
            &global
        } else {
            interface
                .addrs
                .iter()
                .find(|addr| addr.is_ipv4())
                .context("No IPv4 address is available")?
        };
        if let Err(e) = aliddns::update_record(config, addr, id) {
            warn!("{:?}", e);
        } else if !msg.is_empty() {
            write!(msg, ", {}", addr)?;
        } else {
            write!(msg, "{}", addr)?;
        }
    };

    Ok(msg)
}

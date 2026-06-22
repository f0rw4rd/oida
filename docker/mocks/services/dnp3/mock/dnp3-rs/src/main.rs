//! OIDA DNP3 mock outstation.
//!
//! A single env-var-driven DNP3 outstation built on the stepfunc `dnp3` crate
//! (crates.io `dnp3`, https://github.com/stepfunc/dnp3). It replaces the old
//! Python `pydnp3-stepfunc` / FreyrSCADA mocks while preserving the exact
//! env-var contract, ports, and DNP3 addresses used by docker/mocks/compose.yml.
//!
//! All three former variants (basic, enhanced, filetransfer) are served by this
//! one binary; behavior is selected purely by environment variables, so the
//! enhanced feature handlers (cold/warm restart with delays, counter freeze,
//! analog dead-bands, octet strings, device attributes) are always present and
//! only fire when a master actually requests them.
//!
//! Environment variables (superset across all variants):
//!   DNP3_PORT              bind port (default 20000)
//!   DNP3_OUTSTATION_ADDR   outstation link address (default 1024)
//!   DNP3_SLAVE_ADDR        alias for DNP3_OUTSTATION_ADDR (filetransfer variant)
//!   DNP3_MASTER_ADDR       expected master address (default 1)
//!   DNP3_BI_COUNT          binary input count (default 10)
//!   DNP3_AI_COUNT          analog input count (default 10)
//!   DNP3_CT_COUNT          counter count (default 5)
//!   DNP3_BO_COUNT          binary output count (default 5)
//!   DNP3_AO_COUNT          analog output count (default 5)
//!   DNP3_FROZEN_COUNTER_COUNT  frozen counter count (default = CT_COUNT)
//!   DNP3_OCTET_COUNT       octet string (Group 110) count (default 0)
//!   DNP3_UPDATE_INTERVAL   value update interval seconds (default 5)
//!   DNP3_DEVICE_NAME       product name attribute (default "OIDA DNP3 Mock")
//!   DNP3_SERIAL            device serial number attribute
//!   DNP3_SOFTWARE_VERSION  software version attribute (default "1.0.0")
//!   DNP3_HARDWARE_VERSION  hardware version attribute (default "Rev-A")
//!   DNP3_COLD_RESTART_DELAY  cold restart delay seconds (default 60)
//!   DNP3_WARM_RESTART_DELAY  warm restart delay milliseconds (default 5000)
//!   DNP3_TLS               enable TLS ("true"/"1"/"yes")
//!   DNP3_TLS_DNS_NAME      DNS name for TLS cert (default "localhost")
//!   DNP3_FILE_DIR          sample-file directory, created at startup (default /app/files)
//!   DNP3_LOG_LEVEL         DEBUG/INFO/WARN/ERROR (default INFO)
//!
//! A `--healthcheck` argument performs a TCP connect to 127.0.0.1:$DNP3_PORT and
//! exits 0/1, so the container needs no Python interpreter for its healthcheck.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use dnp3::app::attr::{AttrProp, Attribute, StringAttr};
use dnp3::app::control::*;
use dnp3::app::measurement::*;
use dnp3::app::*;
use dnp3::link::*;
use dnp3::outstation::database::*;
use dnp3::outstation::*;
use dnp3::tcp::tls::*;
use dnp3::tcp::*;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct Config {
    port: u16,
    outstation_addr: u16,
    master_addr: u16,
    bi: u16,
    ai: u16,
    ct: u16,
    bo: u16,
    ao: u16,
    frozen_ct: u16,
    octet: u16,
    update_interval: f64,
    device_name: String,
    serial: String,
    software_version: String,
    hardware_version: String,
    cold_restart_secs: u16,
    warm_restart_ms: u16,
    tls: bool,
    tls_dns_name: String,
    file_dir: String,
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<T>().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    )
}

impl Config {
    fn from_env() -> Self {
        let ct: u16 = env_parse("DNP3_CT_COUNT", 5);
        // DNP3_SLAVE_ADDR (filetransfer) is an alias for DNP3_OUTSTATION_ADDR.
        let outstation_addr = std::env::var("DNP3_OUTSTATION_ADDR")
            .ok()
            .or_else(|| std::env::var("DNP3_SLAVE_ADDR").ok())
            .and_then(|v| v.trim().parse::<u16>().ok())
            .unwrap_or(1024);
        Config {
            port: env_parse("DNP3_PORT", 20000),
            outstation_addr,
            master_addr: env_parse("DNP3_MASTER_ADDR", 1),
            bi: env_parse("DNP3_BI_COUNT", 10),
            ai: env_parse("DNP3_AI_COUNT", 10),
            ct,
            bo: env_parse("DNP3_BO_COUNT", 5),
            ao: env_parse("DNP3_AO_COUNT", 5),
            frozen_ct: env_parse("DNP3_FROZEN_COUNTER_COUNT", ct),
            octet: env_parse("DNP3_OCTET_COUNT", 0),
            update_interval: env_parse("DNP3_UPDATE_INTERVAL", 5.0),
            device_name: env_str("DNP3_DEVICE_NAME", "OIDA DNP3 Mock"),
            serial: env_str("DNP3_SERIAL", "OIDA-DNP3-001"),
            software_version: env_str("DNP3_SOFTWARE_VERSION", "1.0.0"),
            hardware_version: env_str("DNP3_HARDWARE_VERSION", "Rev-A"),
            cold_restart_secs: env_parse("DNP3_COLD_RESTART_DELAY", 60),
            warm_restart_ms: env_parse("DNP3_WARM_RESTART_DELAY", 5000),
            tls: env_bool("DNP3_TLS"),
            tls_dns_name: env_str("DNP3_TLS_DNS_NAME", "localhost"),
            file_dir: env_str("DNP3_FILE_DIR", "/app/files"),
        }
    }
}

// ---------------------------------------------------------------------------
// Application handler: device attrs, restart, freeze, dead-bands
// ---------------------------------------------------------------------------

struct OidaApplication {
    cold_restart_secs: u16,
    warm_restart_ms: u16,
}

impl OutstationApplication for OidaApplication {
    fn get_processing_delay_ms(&self) -> u16 {
        // Non-zero so DELAY_MEASURE returns a meaningful value.
        10
    }

    fn cold_restart(&mut self) -> Option<RestartDelay> {
        tracing::info!("COLD RESTART requested -> {} s", self.cold_restart_secs);
        Some(RestartDelay::Seconds(self.cold_restart_secs))
    }

    fn warm_restart(&mut self) -> Option<RestartDelay> {
        tracing::info!("WARM RESTART requested -> {} ms", self.warm_restart_ms);
        Some(RestartDelay::Milliseconds(self.warm_restart_ms))
    }

    fn freeze_counter(
        &mut self,
        indices: FreezeIndices,
        freeze_type: FreezeType,
        database: &mut DatabaseHandle,
    ) -> Result<(), RequestError> {
        tracing::info!("FREEZE counters: indices={indices:?} type={freeze_type:?}");
        let clear = matches!(freeze_type, FreezeType::FreezeAndClear);
        database.transaction(|db| {
            let do_one = |db: &mut Database, i: u16| {
                let current: Option<Counter> = db.get(i);
                if let Some(c) = current {
                    db.update(
                        i,
                        &FrozenCounter::new(c.value, Flags::ONLINE, now_time()),
                        UpdateOptions::detect_event(),
                    );
                    if clear {
                        db.update(
                            i,
                            &Counter::new(0, Flags::ONLINE, now_time()),
                            UpdateOptions::detect_event(),
                        );
                    }
                }
            };
            match indices {
                FreezeIndices::All => {
                    for i in 0..u16::MAX {
                        let exists: Option<Counter> = db.get(i);
                        if exists.is_none() {
                            break;
                        }
                        do_one(db, i);
                    }
                }
                FreezeIndices::Range(start, stop) => {
                    for i in start..=stop {
                        do_one(db, i);
                    }
                }
            }
        });
        Ok(())
    }

    fn support_write_analog_dead_bands(&mut self) -> bool {
        true
    }

    fn write_analog_dead_band(&mut self, index: u16, dead_band: f64) {
        tracing::info!("WRITE DEAD BAND index={index} value={dead_band}");
    }

    fn write_device_attr(&mut self, attr: Attribute) -> MaybeAsync<bool> {
        tracing::info!("write device attribute: {attr:?}");
        MaybeAsync::ready(true)
    }
}

struct OidaInformation;
impl OutstationInformation for OidaInformation {}

// ---------------------------------------------------------------------------
// Control handler: binary outputs (g12) + analog outputs (g41 v1-v4)
// ---------------------------------------------------------------------------

struct OidaControlHandler {
    bo: u16,
    ao: u16,
}

impl ControlHandler for OidaControlHandler {}

impl OidaControlHandler {
    fn select_ao(&self, index: u16) -> CommandStatus {
        if index < self.ao {
            CommandStatus::Success
        } else {
            CommandStatus::NotSupported
        }
    }

    fn operate_ao(&self, value: f64, index: u16, database: &mut DatabaseHandle) -> CommandStatus {
        if index < self.ao {
            database.transaction(|db| {
                db.update(
                    index,
                    &AnalogOutputStatus::new(value, Flags::ONLINE, now_time()),
                    UpdateOptions::detect_event(),
                );
            });
            CommandStatus::Success
        } else {
            CommandStatus::NotSupported
        }
    }
}

impl ControlSupport<Group12Var1> for OidaControlHandler {
    fn select(
        &mut self,
        _control: Group12Var1,
        index: u16,
        _db: &mut DatabaseHandle,
    ) -> CommandStatus {
        if index < self.bo {
            CommandStatus::Success
        } else {
            CommandStatus::NotSupported
        }
    }

    fn operate(
        &mut self,
        control: Group12Var1,
        index: u16,
        _op_type: OperateType,
        database: &mut DatabaseHandle,
    ) -> CommandStatus {
        if index < self.bo {
            let status =
                control.code.op_type == OpType::LatchOn || control.code.op_type == OpType::PulseOn;
            database.transaction(|db| {
                db.update(
                    index,
                    &BinaryOutputStatus::new(status, Flags::ONLINE, now_time()),
                    UpdateOptions::detect_event(),
                );
            });
            CommandStatus::Success
        } else {
            CommandStatus::NotSupported
        }
    }
}

macro_rules! analog_output_support {
    ($t:ty) => {
        impl ControlSupport<$t> for OidaControlHandler {
            fn select(
                &mut self,
                _control: $t,
                index: u16,
                _db: &mut DatabaseHandle,
            ) -> CommandStatus {
                self.select_ao(index)
            }
            fn operate(
                &mut self,
                control: $t,
                index: u16,
                _op_type: OperateType,
                database: &mut DatabaseHandle,
            ) -> CommandStatus {
                self.operate_ao(control.value as f64, index, database)
            }
        }
    };
}

analog_output_support!(Group41Var1);
analog_output_support!(Group41Var2);
analog_output_support!(Group41Var3);
analog_output_support!(Group41Var4);

// ---------------------------------------------------------------------------
// Database init + periodic updates
// ---------------------------------------------------------------------------

fn now_time() -> Time {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Time::Synchronized(Timestamp::new(ms))
}

fn init_database(outstation: &OutstationHandle, cfg: &Config) {
    outstation.transaction(|db| {
        for i in 0..cfg.bi {
            db.add(
                i,
                Some(EventClass::Class1),
                BinaryInputConfig {
                    s_var: StaticBinaryInputVariation::Group1Var2,
                    e_var: EventBinaryInputVariation::Group2Var2,
                },
            );
        }
        for i in 0..cfg.ai {
            db.add(
                i,
                Some(EventClass::Class1),
                AnalogInputConfig {
                    s_var: StaticAnalogInputVariation::Group30Var5,
                    e_var: EventAnalogInputVariation::Group32Var5,
                    deadband: 0.0,
                },
            );
        }
        for i in 0..cfg.ct {
            db.add(i, Some(EventClass::Class1), CounterConfig::default());
        }
        for i in 0..cfg.frozen_ct {
            db.add(i, Some(EventClass::Class1), FrozenCounterConfig::default());
        }
        for i in 0..cfg.bo {
            db.add(
                i,
                Some(EventClass::Class1),
                BinaryOutputStatusConfig::default(),
            );
        }
        for i in 0..cfg.ao {
            db.add(
                i,
                Some(EventClass::Class1),
                AnalogOutputStatusConfig::default(),
            );
        }
        for i in 0..cfg.octet {
            db.add(i, Some(EventClass::Class1), OctetStringConfig);
        }

        // Device attributes (Group 0)
        let _ = db.define_attr(
            AttrProp::default(),
            StringAttr::DeviceManufacturersName.with_value("OIDA Mock"),
        );
        let _ = db.define_attr(
            AttrProp::default(),
            StringAttr::ProductNameAndModel.with_value(&cfg.device_name),
        );
        let _ = db.define_attr(
            AttrProp::default(),
            StringAttr::DeviceSerialNumber.with_value(&cfg.serial),
        );
        let _ = db.define_attr(
            AttrProp::writable(),
            StringAttr::UserAssignedLocation
                .with_value(&format!("Outstation {} - OIDA Test", cfg.outstation_addr)),
        );
        let _ = db.define_attr(
            AttrProp::default(),
            StringAttr::DeviceManufacturerSoftwareVersion.with_value(&cfg.software_version),
        );
        let _ = db.define_attr(
            AttrProp::default(),
            StringAttr::DeviceManufacturerHardwareVersion.with_value(&cfg.hardware_version),
        );

        // Initial octet string values
        let labels = ["firmware-hash", "config-rev", "vendor-blob"];
        for i in 0..cfg.octet {
            let label = labels
                .get(i as usize)
                .copied()
                .unwrap_or("octet")
                .as_bytes();
            if let Ok(os) = OctetString::new(label) {
                db.update(i, &os, UpdateOptions::detect_event());
            }
        }
    });
}

fn update_values(outstation: &OutstationHandle, cfg: &Config, cycle: u64) {
    outstation.transaction(|db| {
        for i in 0..cfg.bi {
            let val = ((cycle + i as u64) % 4) < 2;
            db.update(
                i,
                &BinaryInput::new(val, Flags::ONLINE, now_time()),
                UpdateOptions::detect_event(),
            );
        }
        for i in 0..cfg.ai {
            let val = 100.0 + (i as f64) * 10.0 + 5.0 * ((cycle as f64) * 0.1 + i as f64).sin();
            db.update(
                i,
                &AnalogInput::new(val, Flags::ONLINE, now_time()),
                UpdateOptions::detect_event(),
            );
        }
        for i in 0..cfg.ct {
            let val = (cycle * (i as u64 + 1)) as u32;
            db.update(
                i,
                &Counter::new(val, Flags::ONLINE, now_time()),
                UpdateOptions::detect_event(),
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Sample files (filetransfer variant parity; the stepfunc outstation does not
// serve Group 70, but the directory is created for parity with the old mock).
// ---------------------------------------------------------------------------

fn create_sample_files(dir: &str) {
    let base = Path::new(dir);
    if std::fs::create_dir_all(base).is_err() {
        return;
    }
    let files: [(&str, &str); 3] = [
        (
            "config.txt",
            "# DNP3 Outstation Configuration\nslave_address=1\nmaster_address=2\n",
        ),
        (
            "firmware_info.txt",
            "Firmware: OIDA-DNP3-FT v1.0.0\nHardware: Rev-B\nSerial: OIDA-FT-001\n",
        ),
        (
            "event_log.csv",
            "timestamp,group,index,value,quality\n2025-01-15T10:00:00,BI,0,1,ONLINE\n",
        ),
    ];
    for (name, content) in files {
        let _ = std::fs::write(base.join(name), content);
    }
    let sub = base.join("subdir");
    let _ = std::fs::create_dir_all(&sub);
    let _ = std::fs::write(sub.join("nested_file.txt"), "nested file\n");
}

// ---------------------------------------------------------------------------
// TLS cert generation (self-signed, via openssl CLI present in runtime image)
// ---------------------------------------------------------------------------

fn ensure_tls_certs(dns_name: &str) -> Result<(String, String, String), String> {
    let dir = "/app/certs";
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let key = format!("{dir}/server-key.pem");
    let cert = format!("{dir}/server.pem");
    let client = format!("{dir}/client.pem");
    if !Path::new(&cert).exists() || !Path::new(&key).exists() {
        let subj = format!("/CN={dns_name}/O=OIDA Test");
        let san = format!("subjectAltName=DNS:{dns_name},DNS:localhost,IP:127.0.0.1");
        let status = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-keyout", &key, "-out", &cert, "-days",
                "365", "-nodes", "-subj", &subj, "-addext", &san,
            ])
            .status()
            .map_err(|e| format!("openssl: {e}"))?;
        if !status.success() {
            return Err("openssl cert generation failed".into());
        }
        // Use the same self-signed cert as the expected peer cert.
        std::fs::copy(&cert, &client).map_err(|e| e.to_string())?;
    }
    Ok((cert.clone(), key, client))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn outstation_config(cfg: &Config) -> OutstationConfig {
    let mut config = OutstationConfig::new(
        EndpointAddress::try_new(cfg.outstation_addr).unwrap(),
        EndpointAddress::try_new(cfg.master_addr).unwrap(),
        EventBufferConfig::new(
            cfg.bi.max(25),
            10,
            cfg.bo.max(10),
            cfg.ct.max(10),
            cfg.frozen_ct.max(10),
            cfg.ai.max(25),
            cfg.ao.max(10),
            cfg.octet.max(3),
        ),
    );
    config.class_zero.octet_string = true;
    config
}

fn healthcheck() -> ! {
    let port: u16 = env_parse("DNP3_PORT", 20000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--healthcheck") {
        healthcheck();
    }

    let level = match env_str("DNP3_LOG_LEVEL", "INFO").to_uppercase().as_str() {
        "DEBUG" => tracing::Level::DEBUG,
        "WARN" | "WARNING" => tracing::Level::WARN,
        "ERROR" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    let cfg = Config::from_env();
    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.port);

    tracing::info!("OIDA DNP3 outstation (stepfunc dnp3 crate)");
    tracing::info!(
        "  bind={bind} outstation_addr={} master_addr={}",
        cfg.outstation_addr,
        cfg.master_addr
    );
    tracing::info!(
        "  points: {} BI, {} AI, {} CT, {} FCT, {} BO, {} AO, {} OS",
        cfg.bi,
        cfg.ai,
        cfg.ct,
        cfg.frozen_ct,
        cfg.bo,
        cfg.ao,
        cfg.octet
    );
    tracing::info!(
        "  device='{}' serial='{}' tls={}",
        cfg.device_name,
        cfg.serial,
        cfg.tls
    );

    // Always create the sample-file directory (filetransfer parity).
    create_sample_files(&cfg.file_dir);

    let mut server = if cfg.tls {
        let (cert, key, client) = ensure_tls_certs(&cfg.tls_dns_name).map_err(|e| {
            tracing::error!("TLS setup failed: {e}");
            e
        })?;
        let tls_config = TlsServerConfig::self_signed(
            Path::new(&client),
            Path::new(&cert),
            Path::new(&key),
            None,
            MinTlsVersion::V12,
        )?;
        tracing::info!("TLS enabled (self-signed, mutual cert validation)");
        Server::new_tls_server(LinkErrorMode::Close, bind, tls_config)
    } else {
        Server::new_tcp_server(LinkErrorMode::Close, bind)
    };

    let outstation = server.add_outstation(
        outstation_config(&cfg),
        Box::new(OidaApplication {
            cold_restart_secs: cfg.cold_restart_secs,
            warm_restart_ms: cfg.warm_restart_ms,
        }),
        Box::new(OidaInformation),
        Box::new(OidaControlHandler {
            bo: cfg.bo,
            ao: cfg.ao,
        }),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    init_database(&outstation, &cfg);

    let _server_handle = server.bind().await?;
    tracing::info!("server bound and accepting connections on {bind}");

    // Periodic value updates until SIGTERM/SIGINT.
    let interval = Duration::from_secs_f64(cfg.update_interval.max(0.1));
    let mut cycle: u64 = 0;
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // consume immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                cycle += 1;
                update_values(&outstation, &cfg, cycle);
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            _ = wait_for_sigterm() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn wait_for_sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
            return;
        }
    }
    // Fallback: never resolves.
    std::future::pending::<()>().await
}

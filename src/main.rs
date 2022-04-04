#[macro_use] extern crate rocket;

use std::path::PathBuf;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
use std::borrow::Cow;

use tokio::net::TcpStream;
use torut::onion::{TorSecretKeyV3, OnionAddressV3};
use torut::control::{Conn, UnauthenticatedConn, TorAuthData, ConnError};

use libtor::{Tor, TorFlag, LogLevel, LogDestination};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Config {
    tor_datadir: PathBuf,
    onion_key: TorSecretKeyV3,
    listen_port: u16,
}

async fn start_tor(config: &Config) -> Result<SocketAddr, ConnError> {
    let random_password = "thisshouldberandombutidontwanttoaddextradependencies";
    let control_file = config.tor_datadir.join("control-port.txt");

    Tor::new()
        .flag(TorFlag::DataDirectory(config.tor_datadir.display().to_string()))
        .flag(TorFlag::LogTo(LogLevel::Notice, LogDestination::File(config.tor_datadir.join("log.txt").display().to_string())))

        .flag(TorFlag::ControlPortAuto)
        .flag(TorFlag::ControlPortWriteToFile(control_file.display().to_string()))
        .flag(TorFlag::HashedControlPassword(libtor::generate_hashed_password(&random_password)))

        .flag(TorFlag::SocksPortAuto)

        .start_background();

    // wait for the control file to become available
    let control_addr = loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        match std::fs::read_to_string(&control_file).ok().and_then(|content| content.replace("PORT=", "").trim_end().parse::<SocketAddr>().ok()) {
            Some(port) => break port,
            None => continue,
        }

        // TODO: add timeout
    };

    let stream = TcpStream::connect(control_addr).await.expect("Unable to connect");
    let mut conn = UnauthenticatedConn::from(Conn::new(stream));
    conn.authenticate(&TorAuthData::HashedPassword(Cow::Borrowed(random_password))).await?;
    let mut auth_conn = conn.into_authenticated().await;
    auth_conn.set_async_event_handler(Some(|_| {
        async {
            Ok(())
        }
    }));

    auth_conn.add_onion_v3(&config.onion_key, true, false, false, None, &mut vec![(config.listen_port, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), config.listen_port)))].iter()).await?;

    Ok(auth_conn.get_info("net/listeners/socks").await?.replace('"', "").parse::<SocketAddr>().expect("Invalid SocksPort"))
}

#[get("/hello")]
fn hello() -> &'static str {
    "Hello World!"
}

#[launch]
async fn rocket() -> _ {
    let config = match std::fs::read_to_string("config.json").ok().and_then(|conf| serde_json::from_str(&conf).ok()) {
        Some(config) => config,
        None => {
            let config = Config {
                tor_datadir: PathBuf::from("/tmp/tor-datadir"),
                onion_key: TorSecretKeyV3::generate(),
                listen_port: 8000,
            };
            std::fs::write("config.json", &serde_json::to_string(&config).unwrap()).unwrap();

            config
        }
    };

    let socks_proxy = start_tor(&config).await.unwrap();
    println!("Onion address: {}:{}", OnionAddressV3::from(&config.onion_key.public()), config.listen_port);
    println!("Socks port: {}", socks_proxy);

    rocket::custom(&rocket::Config {
        port: config.listen_port,
        ..rocket::Config::debug_default()
    }).mount("/", routes![hello])
}

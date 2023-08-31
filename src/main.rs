use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    http::StatusCode,
    routing::{get, post},
};
use log::{error, info};
use netty::{Handshake, NettyReadError};
use quinn::{Connecting, ConnectionError, Endpoint, ServerConfig, TransportConfig};
use routing::RoutingTable;
use rustls::{Certificate, PrivateKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    netty::WriteExtNetty,
    proto::{ClientboundControlMessage, ServerboundControlMessage},
};

mod netty;
mod proto;
mod routing;
mod validation;
mod wordlist;

fn any_private_keys(rd: &mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error> {
    let mut keys = Vec::<Vec<u8>>::new();

    loop {
        match rustls_pemfile::read_one(rd)? {
            None => return Ok(keys),
            Some(rustls_pemfile::Item::ECKey(key)) => keys.push(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => keys.push(key),
            Some(rustls_pemfile::Item::RSAKey(key)) => keys.push(key),
            _ => {}
        };
    }
}

fn get_certs() -> anyhow::Result<(Vec<Certificate>, PrivateKey)> {
    let mut cert_file = std::io::BufReader::new(std::fs::File::open(
        std::env::var("QUICLIME_CERT_PATH").context("Reading QUICLIME_CERT_PATH")?,
    )?);
    let certs = rustls_pemfile::certs(&mut cert_file)?
        .into_iter()
        .map(Certificate)
        .collect();
    let mut key_file = std::io::BufReader::new(std::fs::File::open(
        std::env::var("QUICLIME_KEY_PATH").context("Reading QUICLIME_KEY_PATH")?,
    )?);
    let key = PrivateKey(
        any_private_keys(&mut key_file)?
            .into_iter()
            .next()
            .ok_or(anyhow::anyhow!("No private key?"))?,
    );
    Ok((certs, key))
}

async fn create_server_config() -> anyhow::Result<ServerConfig> {
    let (cert_chain, key_der) = tokio::task::spawn_blocking(get_certs).await??;
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    rustls_config.alpn_protocols = vec![b"quiclime".to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(rustls_config));
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    let endpoint = Box::leak(Box::new(Endpoint::server(
        create_server_config().await?,
        std::env::var("QUICLIME_BIND_ADDR_QUIC")
            .context("Reading QUICLIME_BIND_ADDR_QUIC")?
            .parse()?,
    )?));
    
    let routing_table = Box::leak(Box::new(routing::RoutingTable::new(
        std::env::var("QUICLIME_BASE_DOMAIN").context("Reading QUICLIME_BASE_DOMAIN")?,
    )));
    tokio::try_join!(
        listen_quic(endpoint, routing_table),
        listen_control(endpoint, routing_table),
        listen_minecraft(routing_table)
    )?;
    Ok(())
}

async fn try_handle_quic(
    connection: Connecting,
    routing_table: &RoutingTable,
) -> anyhow::Result<()> {
    let connection = connection.await?;
    info!(
        "QUIClime connection established to: {}",
        connection.remote_address()
    );
    let (mut send_control, mut recv_control) = connection.accept_bi().await?;
    info!("Control channel open: {}", connection.remote_address());
    let mut handle = loop {
        let mut buf = vec![0u8; recv_control.read_u8().await? as _];
        recv_control.read_exact(&mut buf).await?;
        if let Ok(parsed) = serde_json::from_slice(&buf) {
            match parsed {
                ServerboundControlMessage::RequestDomainAssignment => {
                    let handle = routing_table.register().await;
                    info!(
                        "Domain assigned to {}: {}",
                        connection.remote_address(),
                        handle.domain()
                    );
                    let response =
                        serde_json::to_vec(&ClientboundControlMessage::DomainAssignmentComplete {
                            domain: handle.domain().to_string(),
                        })?;
                    send_control.write_all(&[response.len() as u8]).await?;
                    send_control.write_all(&response).await?;
                    break handle;
                }
            }
        } else {
            let response = serde_json::to_vec(&ClientboundControlMessage::UnknownMessage)?;
            send_control.write_all(&[response.len() as u8]).await?;
            send_control.write_all(&response).await?;
        }
    };
    tokio::select! {
        e = connection.closed() => {
            match e {
                ConnectionError::ConnectionClosed(_) => Ok(()),
                ConnectionError::ApplicationClosed(_) => Ok(()),
                ConnectionError::LocallyClosed => Ok(()),
                e => Err(e.into())
            }
        },
        r = async {
            while let Some(remote) = handle.next().await {
                match remote {
                    routing::RouterRequest::RouteRequest(remote) => {
                        let pair = connection.open_bi().await;
                        if let Err(ConnectionError::ApplicationClosed(_)) = pair {
                            break;
                        } else if let Err(ConnectionError::ConnectionClosed(_)) = pair {
                            break;
                        }
                        remote.send(pair?).map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    }
                    routing::RouterRequest::BroadcastRequest(message) => {
                        let response =
                            serde_json::to_vec(&ClientboundControlMessage::RequestMessageBroadcast {
                                message,
                            })?;
                        send_control.write_all(&[response.len() as u8]).await?;
                        send_control.write_all(&response).await?;
                    }
                }
            }
            Ok(())
        } => r
    }
}

async fn handle_quic(connection: Connecting, routing_table: &RoutingTable) {
    if let Err(e) = try_handle_quic(connection, routing_table).await {
        error!("Error handling QUIClime connection: {}", e);
    };
    info!("Finished handling QUIClime connection");
}

async fn listen_quic(
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
) -> anyhow::Result<()> {
    while let Some(connection) = endpoint.accept().await {
        tokio::spawn(handle_quic(connection, routing_table));
    }
    Ok(())
}

async fn listen_control(
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route(
            "/metrics",
            get(|| async { format!("host_count {}", routing_table.size()) }),
        )
        .route(
            "/reload-certs",
            post(|| async {
                match create_server_config().await {
                    Ok(config) => {
                        endpoint.set_server_config(Some(config));
                        (StatusCode::OK, "Success".to_string())
                    }
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)),
                }
            }),
        )
        .route(
            "/broadcast",
            post(move |body: String| async move { routing_table.broadcast(&body) }),
        )
        .route(
            "/stop",
            post(|| async {
                endpoint.close(0u32.into(), b"concrete closing");
            }),
        );
    axum::Server::bind(
        &std::env::var("QUICLIME_BIND_ADDR_WEB")
            .context("Reading QUICLIME_BIND_ADDR_WEB")?
            .parse()?,
    )
    .serve(app.into_make_service())
    .await?;
    Ok(())
}

async fn try_handle_minecraft(
    mut connection: TcpStream,
    routing_table: &'static RoutingTable,
) -> anyhow::Result<()> {
    let peer = connection.peer_addr()?;
    info!("Minecraft client connected from: {}", peer);
    let handshake = netty::read_packet(&mut connection).await;
    if let Err(NettyReadError::LegacyServerListPing) = handshake {
        connection
            .write_all(include_bytes!("legacy_serverlistping_response.bin"))
            .await?;
        return Ok(());
    }
    let handshake = Handshake::new(&handshake?)?;
    let address = match handshake.normalized_address() {
        Some(addr) => addr,
        None => return politely_disconnect(connection, handshake).await,
    };
    let (mut send_host, mut recv_host) = match routing_table.route(&address).await {
        Some(pair) => pair,
        None => return politely_disconnect(connection, handshake).await,
    };
    handshake.send(&mut send_host).await?;
    let (mut recv_client, mut send_client) = connection.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv_client, &mut send_host) => (),
        _ = tokio::io::copy(&mut recv_host, &mut send_client) => ()
    }
    _ = connection.shutdown().await;
    _ = send_host.finish().await;
    _ = recv_host.stop(0u32.into());
    info!("Minecraft client disconnected from: {}", peer);
    Ok(())
}

async fn politely_disconnect(
    mut connection: TcpStream,
    handshake: Handshake,
) -> anyhow::Result<()> {
    match handshake.next_state {
        netty::HandshakeType::Status => {
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(include_str!("./serverlistping_response.json"))
                .await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
        netty::HandshakeType::Login => {
            let _ = netty::read_packet(&mut connection).await?;
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(include_str!("./disconnect_response.json"))
                .await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
    }
    Ok(())
}

async fn handle_minecraft(connection: TcpStream, routing_table: &'static RoutingTable) {
    if let Err(e) = try_handle_minecraft(connection, routing_table).await {
        error!("Error handling Minecraft connection: {}", e.backtrace());
    };
}

async fn listen_minecraft(routing_table: &'static RoutingTable) -> anyhow::Result<()> {
    let server = tokio::net::TcpListener::bind(
        std::env::var("QUICLIME_BIND_ADDR_MC")
            .context("Reading QUICLIME_BIND_ADDR_MC")?
            .parse::<SocketAddr>()?,
    )
    .await?;
    while let Ok((connection, _)) = server.accept().await {
        tokio::spawn(handle_minecraft(connection, routing_table));
    }
    Ok(())
}

use std::{cell::RefCell, net::SocketAddr, rc::Rc, time::Instant};

use neqo_common::{
    event::Provider as _,
    Datagram, Tos,
};
use neqo_http3::{
    Http3Client, Http3ClientEvent, Http3Parameters, Http3State, WebTransportEvent,
    Output, webtransport::ClientSession,
};
use neqo_transport::StreamType;
use nss::AuthenticationStatus;
use test_fixture::CountingConnectionIdGenerator;

fn recv_datagram(socket: &std::net::UdpSocket, local_addr: SocketAddr) -> Result<Option<Datagram>, std::io::Error> {
    let mut buf = vec![0u8; 65535];
    match socket.recv_from(&mut buf) {
        Ok((size, peer)) => {
            let data = buf.into_boxed_slice();
            Ok(Some(Datagram::new(peer, local_addr, Tos::default(), &data[..size])))
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

fn main() {
    let _ = nss::init();

    let server_name = "localhost";
    // Connect via IPv6 loopback to the server listening on [::]:4433
    let server_addr: SocketAddr = "[::1]:4433".parse().unwrap();
    let local_addr: SocketAddr = "[::1]:0".parse().unwrap();

    eprintln!("=== YAWT WebTransport Test Client ===");
    eprintln!("SNI: {}", server_name);
    eprintln!("Server: {}", server_addr);

    let mut client = Http3Client::new(
        server_name,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        local_addr,
        server_addr,
        Http3Parameters::default().webtransport(true),
        Instant::now(),
    )
    .expect("create client");

    eprintln!("Initial state: {:?}", client.state());

    let socket = std::net::UdpSocket::bind(local_addr).expect("bind socket");
    socket.connect(server_addr).expect("connect socket");
    socket.set_nonblocking(true).ok();

    let timeout = Instant::now() + std::time::Duration::from_secs(30);
    let mut packet_count = 0;

    loop {
        // --- Process events ---
        let mut events_drained = false;
        while let Some(event) = client.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    eprintln!("[auth] AuthenticationNeeded - accepting");
                    client.authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::StateChange(state) => {
                    eprintln!("[state] -> {:?}", state);
                    if state == Http3State::Connected {
                        eprintln!("\n=== HTTP/3 Connected ===");
                        eprintln!("(waiting for WebTransport negotiation before creating session)");
                    }
                }
                Http3ClientEvent::WebTransport(WebTransportEvent::Negotiated(succeeded)) => {
                    eprintln!("\n=== WebTransport Negotiated: {} ===", succeeded);
                    if succeeded {
                        let result = client.webtransport_create_session(
                            Instant::now(),
                            ("https", server_name, "/"),
                            &[],
                        );
                        match result {
                            Ok(session) => eprintln!("WT session requested: {:?}", session),
                            Err(e) => eprintln!("WT create session error: {:?}", e),
                        }
                    } else {
                        eprintln!("WebTransport not negotiated by server; aborting");
                    }
                }
                Http3ClientEvent::WebTransport(WebTransportEvent::NewSession {
                    stream_id,
                    status,
                    headers,
                }) => {
                    eprintln!("\n=== WT Session Established ===");
                    eprintln!("  stream_id: {:?}, status: {}, headers: {:?}", stream_id, status, headers);

                    let wt_stream_id = client
                        .webtransport_create_stream(stream_id, StreamType::BiDi)
                        .expect("create stream");
                    eprintln!("Created bidirectional stream: {:?}", wt_stream_id);

                    let data = b"Hello from neqo!";
                    match client.send_data(wt_stream_id, data, Instant::now()) {
                        Ok(n) => eprintln!("Sent {} bytes on stream", n),
                        Err(e) => eprintln!("Error sending data: {:?}", e),
                    }
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    eprintln!("[data] Readable on stream {:?}", stream_id);
                    let mut buf = vec![0u8; 1024];
                    match client.read_data(Instant::now(), stream_id, &mut buf) {
                        Ok((amount, fin)) => {
                            eprintln!("  Read {} bytes, fin: {}", amount, fin);
                            if amount > 0 {
                                eprintln!("  Data: {:?}", String::from_utf8_lossy(&buf[..amount]));
                            }
                        }
                        Err(e) => eprintln!("  Read error: {:?}", e),
                    }
                }
                _ => {
                    eprintln!("[event] {:?}", event);
                }
            }
            events_drained = true;
        }

        // If we processed events, loop back immediately
        if events_drained {
            continue;
        }

        // --- Get output ---
        let out = client.process_output(Instant::now());

        match out {
            Output::Datagram(dgram) => {
                packet_count += 1;
                eprintln!("[send #{}] {} bytes", packet_count, dgram.len());
                if let Err(e) = socket.send(&dgram) {
                    eprintln!("[send] Error: {}", e);
                }
            }
            Output::Callback(cb) => {
                let wait_time = cb.max(std::time::Duration::from_millis(100));
                eprintln!("[timer] {}ms", wait_time.as_millis());
                socket.set_read_timeout(Some(wait_time)).ok();
                socket.set_nonblocking(false).ok();

                match recv_datagram(&socket, local_addr) {
                    Ok(Some(dgram)) => {
                        eprintln!("[recv] {} bytes", dgram.len());
                        client.process_input(dgram, Instant::now());
                    }
                    Ok(None) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => {
                        eprintln!("[recv] Error: {}", e);
                        break;
                    }
                }
                socket.set_nonblocking(true).ok();
                socket.set_read_timeout(None).ok();
            }
            Output::None => {
                eprintln!("[done] No more output");
                break;
            }
        }

        if Instant::now() >= timeout {
            eprintln!("\n=== Timeout ===");
            break;
        }
    }

    eprintln!("\n=== Test completed ===");
}

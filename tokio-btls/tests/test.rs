use std::{net::ToSocketAddrs, pin::Pin};

use btls::{
    pkey::PKey,
    ssl::{
        FingerprintProfile, Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod,
        TlsClientOptions,
    },
};
use futures::future;
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use tokio_btls::SslStream;

fn x25519_private_key_to_der(private_key: [u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&private_key);
    der
}

fn x25519_public_from_private(private_key: [u8; 32]) -> [u8; 32] {
    let der = x25519_private_key_to_der(private_key);
    let pkey = PKey::private_key_from_der(&der).unwrap();
    let mut public_key = [0u8; 32];
    let raw_public_key = pkey.raw_public_key(&mut public_key).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(raw_public_key);
    out
}

fn extract_x25519_key_share(handshake: &[u8]) -> [u8; 32] {
    assert_eq!(handshake[0], 0x01);

    let mut pos = 4;
    pos += 2 + 32;

    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    let compression_methods_len = handshake[pos] as usize;
    pos += 1 + compression_methods_len;

    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        let ext = &handshake[pos..pos + ext_len];
        if ext_type == 0x0033 {
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            let mut key_share_pos = 2;
            let key_share_end = 2 + list_len;

            while key_share_pos + 4 <= key_share_end {
                let group = u16::from_be_bytes([ext[key_share_pos], ext[key_share_pos + 1]]);
                let key_len =
                    u16::from_be_bytes([ext[key_share_pos + 2], ext[key_share_pos + 3]]) as usize;
                key_share_pos += 4;

                if group == 0x001d && key_len == 32 {
                    let mut key_share = [0u8; 32];
                    key_share.copy_from_slice(&ext[key_share_pos..key_share_pos + 32]);
                    return key_share;
                }

                key_share_pos += key_len;
            }
        }

        pos += ext_len;
    }

    panic!("missing X25519 key share");
}

#[tokio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let ssl = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap()
        .into_ssl("google.com")
        .unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    Pin::new(&mut stream).connect().await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[tokio::test]
async fn server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();

        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).connect().await.unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}

#[tokio::test]
async fn connect_with_client_hello_patch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        connector
            .apply_client_options(
                &TlsClientOptions::new()
                    .fingerprint_profile(FingerprintProfile::Chrome)
                    .session_tickets(false),
            )
            .unwrap();

        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();

        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream)
            .connect_with_client_hello_patch(|hello| {
                assert_eq!(hello.handshake_bytes()?[0], 0x01);
                let _ = hello.client_random()?;
                let _ = hello.x25519_private_key()?;
                hello.set_session_id([0x5a; 32])?;
                Ok::<_, tokio_btls::ClientHelloError>(())
            })
            .await
            .unwrap();

        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    };

    future::join(server, client).await;
}

#[tokio::test]
async fn captured_client_hello_x25519_private_key_matches_key_share() {
    let (stream, _peer) = duplex(4096);

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .apply_client_options(
            &TlsClientOptions::new()
                .fingerprint_profile(FingerprintProfile::Chrome)
                .session_tickets(false),
        )
        .unwrap();

    let ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();

    let mut stream = SslStream::new(ssl, stream).unwrap();
    Pin::new(&mut stream).build_client_hello().await.unwrap();

    let hello = stream.captured_client_hello().unwrap();
    let private_key = hello.x25519_private_key().unwrap();
    let expected_public_key = x25519_public_from_private(private_key);
    let actual_public_key = extract_x25519_key_share(hello.handshake_bytes().unwrap());

    assert_eq!(expected_public_key, actual_public_key);
}

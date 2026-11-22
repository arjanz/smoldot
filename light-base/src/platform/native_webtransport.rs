// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Native HTTP/3 WebTransport for the JAM platform adapter.
//!
//! Certificate pins are supplied by the JAM peer-identity layer. The verifier
//! also checks P-256, certificate validity and TLS proof of key possession.
//! The bounded actor owns only stream acquisition; byte I/O remains per stream.

use super::{Stream as PlatformStream, SubstreamDirection};
use futures_util::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use wtransport::{
    ClientConfig, Endpoint, VarInt, config::QuicTransportConfig, endpoint::endpoint_side::Client,
    tls::Sha256Digest,
};

const STREAM_QUEUE: usize = 64;
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Lazily initialized: ordinary TCP/Substrate users don't acquire Tokio threads.
pub(super) struct Runtime {
    inner: Mutex<Option<tokio::runtime::Runtime>>,
    closed: AtomicBool,
}

impl Runtime {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<tokio::task::AbortHandle> {
        let mut runtime = self.inner.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native transport closed",
            ));
        }
        if runtime.is_none() {
            *runtime = Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("smoldot-webtransport")
                    .enable_all()
                    .build()?,
            );
        }
        Ok(runtime.as_ref().unwrap().spawn(task).abort_handle())
    }

    pub(super) fn shutdown(&self) {
        let runtime = {
            let mut runtime = self.inner.lock();
            self.closed.store(true, Ordering::Release);
            runtime.take()
        };
        if let Some(runtime) = runtime {
            if tokio::runtime::Handle::try_current().is_ok() {
                // Dropping a platform from inside a Tokio task must not panic.
                runtime.shutdown_background();
            } else {
                runtime.shutdown_timeout(Duration::from_secs(2));
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// All handles and streams retain this owner. The actor itself has only a Weak,
/// so a dropped connection with no remaining streams cancels its network work.
struct Life {
    actor: Mutex<Option<tokio::task::AbortHandle>>,
    session: Mutex<Option<(Endpoint<Client>, wtransport::Connection)>>,
}

impl Drop for Life {
    fn drop(&mut self) {
        if let Some((endpoint, connection)) = self.session.get_mut().take() {
            connection.close(VarInt::from_u32(0), b"client closed");
            drop(endpoint);
        }
        if let Some(actor) = self.actor.get_mut().take() {
            actor.abort();
        }
    }
}

pub struct Connection {
    open: async_channel::Sender<()>,
    streams: async_channel::Receiver<(PlatformStream, SubstreamDirection)>,
    _life: Arc<Life>,
}

impl Connection {
    pub(super) fn new(runtime: &Runtime, ip: IpAddr, port: u16, hashes: Vec<[u8; 32]>) -> Self {
        let (open, requests) = async_channel::bounded(STREAM_QUEUE);
        let (streams_tx, streams) = async_channel::bounded(STREAM_QUEUE);
        let life = Arc::new(Life {
            actor: Mutex::new(None),
            session: Mutex::new(None),
        });
        let actor_life = Arc::downgrade(&life);
        match runtime.spawn(async move {
            if let Err(error) = run(ip, port, hashes, actor_life, requests, streams_tx).await {
                log::debug!(target: "smoldot-webtransport", "connection ended: {error}");
            }
        }) {
            Ok(actor) => *life.actor.lock() = Some(actor),
            Err(error) => {
                log::error!(target: "smoldot-webtransport", "cannot start transport: {error}")
            }
        }
        Self {
            open,
            streams,
            _life: life,
        }
    }

    pub(super) fn open(&self) {
        if self.open.try_send(()).is_err() && !self.open.is_closed() {
            // The platform interface cannot return an opening failure. Terminate
            // the connection instead of dropping ownership or growing a queue.
            self.streams.close();
            if let Some(actor) = self._life.actor.lock().as_ref() {
                actor.abort();
            }
        }
    }

    pub(super) async fn next(&self) -> Option<(PlatformStream, SubstreamDirection)> {
        self.streams.recv().await.ok()
    }
}

async fn run(
    ip: IpAddr,
    port: u16,
    hashes: Vec<[u8; 32]>,
    life: Weak<Life>,
    requests: async_channel::Receiver<()>,
    streams: async_channel::Sender<(PlatformStream, SubstreamDirection)>,
) -> io::Result<()> {
    if hashes.is_empty() || hashes.len() > 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "one to eight certificate pins are required",
        ));
    }
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
        .parse()
        .unwrap();
    let mut config = ClientConfig::builder()
        .with_bind_address(bind)
        .with_server_certificate_hashes(hashes.into_iter().map(Sha256Digest::from))
        .build();
    let mut limits = QuicTransportConfig::default();
    limits.max_concurrent_bidi_streams((STREAM_QUEUE as u32).into());
    // HTTP/3 uses control/QPACK streams; application JAM streams are bidirectional.
    limits.max_concurrent_uni_streams(8u32.into());
    limits.stream_receive_window((256 * 1024u32).into());
    limits.receive_window((4 * 1024 * 1024u32).into());
    limits.send_window(4 * 1024 * 1024);
    limits.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()));
    limits.keep_alive_interval(Some(Duration::from_secs(15)));
    config.quic_config_mut().transport_config(Arc::new(limits));
    let endpoint = Endpoint::client(config)?;
    let address = SocketAddr::new(ip, port);
    // The public PolkaJAM 0.1.29 endpoint requires the draft-02 negotiation
    // header. Current WebTransport servers may ignore this extension header.
    let request = wtransport::endpoint::ConnectOptions::builder(format!("https://{address}/"))
        .add_header("sec-webtransport-http3-draft02", "1")
        // Native clients have an opaque origin. The public PolkaJAM endpoint
        // requires this header, as confirmed by its browser CONNECT exchange.
        .add_header("origin", "null")
        .build();
    let connection = tokio::time::timeout(OPEN_TIMEOUT, endpoint.connect(request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebTransport handshake timed out"))?
        .map_err(io::Error::other)?;
    {
        let Some(owner) = life.upgrade() else {
            return Ok(());
        };
        *owner.session.lock() = Some((endpoint, connection.clone()));
    }
    loop {
        let (pair, direction) = tokio::select! {
            request = requests.recv() => {
                if request.is_err() { return Ok(()); }
                let pair = tokio::time::timeout(OPEN_TIMEOUT, async {
                    connection.open_bi().await.map_err(io::Error::other)?
                        .await.map_err(io::Error::other)
                }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebTransport stream opening timed out"))??;
                (pair, SubstreamDirection::Outbound)
            },
            pair = connection.accept_bi() => (pair.map_err(io::Error::other)?, SubstreamDirection::Inbound),
            _ = connection.closed() => return Ok(()),
        };
        let Some(owner) = life.upgrade() else {
            return Ok(());
        };
        let stream = Stream {
            inner: wtransport::stream::BiStream::join(pair).compat(),
            _life: owner,
            read_closed: false,
            write_closed: false,
        };
        if streams
            .send((PlatformStream::webtransport(stream), direction))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

pub(super) struct Stream {
    inner: Compat<wtransport::stream::BiStream>,
    _life: Arc<Life>,
    read_closed: bool,
    write_closed: bool,
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if !buf.is_empty() && matches!(result, Poll::Ready(Ok(0))) {
            this.read_closed = true;
        }
        result
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_close(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.write_closed = true;
        }
        result
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.write_closed {
            let _ = self
                .inner
                .get_mut()
                .send_mut()
                .reset(webtransport_error_code(0));
        }
        if !self.read_closed {
            let _ = self.inner.get_mut().recv_mut().quic_stream_mut().stop(
                wtransport::quinn::VarInt::from_u64(webtransport_error_code(0).into_inner())
                    .unwrap(),
            );
        }
    }
}

// draft-ietf-webtrans-http3-14, section 4.4: WebTransport application errors
// occupy an HTTP/3 range with the reserved 0x1f*N+0x21 codepoints skipped.
// wtransport 0.7 exposes raw QUIC codes through its AsyncRead/AsyncWrite traits.
const FIRST_APPLICATION_ERROR: u64 = 0x52e4_a40f_a8db;
const LAST_APPLICATION_ERROR: u64 = 0x52e5_ac98_3162;

fn webtransport_error_code(code: u32) -> VarInt {
    let code = u64::from(code);
    VarInt::try_from_u64(FIRST_APPLICATION_ERROR + code + code / 0x1e).unwrap()
}

fn application_error_code(code: u64) -> Option<u32> {
    if !(FIRST_APPLICATION_ERROR..=LAST_APPLICATION_ERROR).contains(&code)
        || (code - 0x21) % 0x1f == 0
    {
        return None;
    }
    let shifted = code - FIRST_APPLICATION_ERROR;
    u32::try_from(shifted - shifted / 0x1f).ok()
}

pub(super) fn reset_code(error: &io::Error) -> Option<u32> {
    let source = error.get_ref()?;
    if let Some(wtransport::quinn::ReadError::Reset(code)) = source.downcast_ref() {
        return application_error_code(code.into_inner());
    }
    if let Some(wtransport::quinn::WriteError::Stopped(code)) = source.downcast_ref() {
        return application_error_code(code.into_inner());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{DefaultPlatform, MultiStreamAddress, PlatformRef};
    use futures_lite::future;
    use std::borrow::Cow;
    use wtransport::{Identity, ServerConfig};

    fn server<F, T>(
        serve: F,
    ) -> (
        tokio::runtime::Runtime,
        u16,
        [u8; 32],
        tokio::task::JoinHandle<Result<(), String>>,
    )
    where
        F: FnOnce(wtransport::Connection) -> T + Send + 'static,
        T: Future<Output = ()> + Send + 'static,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let hash = *identity.certificate_chain().as_ref()[0].hash().as_ref();
        let config = ServerConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_identity(identity)
            .build();
        let endpoint = {
            let _entered = runtime.enter();
            Endpoint::server(config).unwrap()
        };
        let port = endpoint.local_addr().unwrap().port();
        let task = runtime.spawn(async move {
            let session = endpoint
                .accept()
                .await
                .await
                .map_err(|error| error.to_string())?;
            assert_eq!(
                session
                    .headers()
                    .get("sec-webtransport-http3-draft02")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(session.origin(), Some("null"));
            let connection = session.accept().await.map_err(|error| error.to_string())?;
            serve(connection).await;
            Ok(())
        });
        (runtime, port, hash, task)
    }

    async fn limited<T>(future: impl Future<Output = T>) -> T {
        future::or(future, async {
            smol::Timer::after(Duration::from_secs(8)).await;
            panic!("transport deadline");
        })
        .await
    }

    async fn exchange(
        platform: &Arc<DefaultPlatform>,
        stream: &mut Pin<Box<PlatformStream>>,
        mut request: Vec<u8>,
    ) -> Result<Vec<u8>, Option<u32>> {
        let mut response = Vec::new();
        loop {
            let done;
            {
                let mut rw = platform
                    .read_write_access(stream.as_mut())
                    .map_err(|error| platform.stream_reset_code(&error))?;
                if !request.is_empty() && rw.write_bytes_queueable.unwrap_or(0) > 0 {
                    rw.write_from_vec(&mut request);
                    if request.is_empty() {
                        rw.close_write();
                    }
                }
                let available = rw.incoming_buffer_available();
                if available > 0 {
                    response.extend(rw.incoming_bytes_take(available).unwrap().unwrap());
                }
                done = rw.expected_incoming_bytes.is_none();
                if !done {
                    rw.expected_incoming_bytes = Some(1);
                }
            }
            if done {
                return Ok(response);
            }
            platform.wait_read_write_again(stream.as_mut()).await;
        }
    }

    #[test]
    fn native_webtransport_pinned_roundtrip_partial_fin_and_stream_lifetime() {
        let (release, released) = futures_channel::oneshot::channel::<()>();
        let (runtime, port, hash, task) = server(move |connection| async move {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 2];
            while let Some(count) = recv.read(&mut buffer).await.unwrap() {
                request.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(request, b"request");
            send.write_all(b"ab").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            send.write_all(b"cd").await.unwrap();
            send.finish().await.unwrap();
            let _ = released.await;
        });
        let platform = DefaultPlatform::new("test".into(), "1".into());
        smol::block_on(limited(async {
            let mut connection = platform
                .connect_multistream(MultiStreamAddress::WebTransport {
                    ip: "127.0.0.1".parse().unwrap(),
                    port,
                    cert_hashes: Cow::Owned(vec![hash]),
                })
                .await
                .connection;
            platform.open_out_substream(&mut connection);
            let (stream, direction) = platform.next_substream(&mut connection).await.unwrap();
            assert!(matches!(direction, SubstreamDirection::Outbound));
            // Existing streams keep the session alive after its handle is dropped.
            drop(connection);
            assert_eq!(
                exchange(&platform, &mut Box::pin(stream), b"request".to_vec())
                    .await
                    .unwrap(),
                b"abcd"
            );
            release.send(()).unwrap();
        }));
        runtime.block_on(task).unwrap().unwrap();
        platform.shutdown().unwrap();
    }

    #[test]
    fn native_webtransport_refuses_wrong_certificate_pin() {
        let (runtime, port, _, task) = server(|_| async {
            panic!("untrusted session reached application");
        });
        let platform = DefaultPlatform::new("test".into(), "1".into());
        smol::block_on(limited(async {
            let mut connection = platform
                .connect_multistream(MultiStreamAddress::WebTransport {
                    ip: "127.0.0.1".parse().unwrap(),
                    port,
                    cert_hashes: Cow::Owned(vec![[0; 32]]),
                })
                .await
                .connection;
            platform.open_out_substream(&mut connection);
            assert!(platform.next_substream(&mut connection).await.is_none());
        }));
        assert!(runtime.block_on(task).unwrap().is_err());
        platform.shutdown().unwrap();
    }

    #[test]
    fn native_webtransport_preserves_reset_code() {
        let (release, released) = futures_channel::oneshot::channel::<()>();
        let (runtime, reset_port, hash, task) = server(move |connection| async move {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut byte = [0];
            recv.read(&mut byte).await.unwrap();
            send.reset(webtransport_error_code(130)).unwrap();
            let _ = released.await;
        });
        let platform = DefaultPlatform::new("test".into(), "1".into());
        smol::block_on(limited(async {
            let mut connection = platform
                .connect_multistream(MultiStreamAddress::WebTransport {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: reset_port,
                    cert_hashes: Cow::Owned(vec![hash]),
                })
                .await
                .connection;
            platform.open_out_substream(&mut connection);
            let (stream, _) = platform.next_substream(&mut connection).await.unwrap();
            assert_eq!(
                exchange(&platform, &mut Box::pin(stream), vec![1])
                    .await
                    .unwrap_err(),
                Some(130)
            );
            release.send(()).unwrap();
        }));
        runtime.block_on(task).unwrap().unwrap();
        platform.shutdown().unwrap();
    }

    #[test]
    fn native_webtransport_invalid_peer_identity_cannot_use_address_pins() {
        let platform = DefaultPlatform::new("test".into(), "1".into());
        smol::block_on(limited(async {
            let mut connection = platform
                .connect_multistream_with_peer_key(
                    MultiStreamAddress::WebTransport {
                        ip: "127.0.0.1".parse().unwrap(),
                        port: 9,
                        cert_hashes: Cow::Owned(vec![[1; 32]]),
                    },
                    [0; 65],
                )
                .await
                .connection;
            assert!(platform.next_substream(&mut connection).await.is_none());
        }));
        platform.shutdown().unwrap();
    }

    #[test]
    fn native_webtransport_application_error_mapping_boundaries() {
        for code in [0, 1, 6, 29, 30, 31, 130, u32::MAX - 1, u32::MAX] {
            let encoded = webtransport_error_code(code).into_inner();
            assert_eq!(application_error_code(encoded), Some(code));
            assert_ne!((encoded - 0x21) % 0x1f, 0);
        }
        assert_eq!(
            webtransport_error_code(0).into_inner(),
            FIRST_APPLICATION_ERROR
        );
        assert_eq!(
            webtransport_error_code(u32::MAX).into_inner(),
            LAST_APPLICATION_ERROR
        );
        assert_eq!(application_error_code(FIRST_APPLICATION_ERROR - 1), None);
        assert_eq!(application_error_code(LAST_APPLICATION_ERROR + 1), None);
        assert_eq!(application_error_code(FIRST_APPLICATION_ERROR + 30), None);
        assert_eq!(application_error_code(130), None);
    }

    #[test]
    fn native_webtransport_dropped_handshake_releases_owner() {
        let runtime = Runtime::new();
        let connection = Connection::new(&runtime, "127.0.0.1".parse().unwrap(), 9, vec![[0; 32]]);
        let weak = Arc::downgrade(&connection._life);
        drop(connection);
        assert!(weak.upgrade().is_none());
        runtime.shutdown();
    }

    #[test]
    fn native_webtransport_requires_certificate_pins() {
        let runtime = Runtime::new();
        smol::block_on(limited(async {
            let connection = Connection::new(&runtime, "127.0.0.1".parse().unwrap(), 9, vec![]);
            assert!(connection.next().await.is_none());
        }));
        runtime.shutdown();
    }

    #[test]
    fn native_webtransport_delivers_inbound_streams() {
        let (release, released) = futures_channel::oneshot::channel::<()>();
        let (runtime, port, hash, task) = server(move |connection| async move {
            let (mut send, _recv) = connection.open_bi().await.unwrap().await.unwrap();
            send.write_all(b"incoming").await.unwrap();
            send.finish().await.unwrap();
            let _ = released.await;
        });
        let platform = DefaultPlatform::new("test".into(), "1".into());
        smol::block_on(limited(async {
            let mut connection = platform
                .connect_multistream(MultiStreamAddress::WebTransport {
                    ip: "127.0.0.1".parse().unwrap(),
                    port,
                    cert_hashes: Cow::Owned(vec![hash]),
                })
                .await
                .connection;
            let (stream, direction) = platform.next_substream(&mut connection).await.unwrap();
            assert!(matches!(direction, SubstreamDirection::Inbound));
            assert_eq!(
                exchange(&platform, &mut Box::pin(stream), Vec::new())
                    .await
                    .unwrap(),
                b"incoming"
            );
            release.send(()).unwrap();
        }));
        runtime.block_on(task).unwrap().unwrap();
        platform.shutdown().unwrap();
    }

    #[test]
    fn native_webtransport_open_queue_is_bounded() {
        let runtime = Runtime::new();
        let connection = Connection::new(&runtime, "127.0.0.1".parse().unwrap(), 9, vec![[0; 32]]);
        for _ in 0..=STREAM_QUEUE {
            connection.open();
        }
        smol::block_on(limited(async {
            assert!(connection.next().await.is_none());
        }));
        drop(connection);
        runtime.shutdown();
    }
}

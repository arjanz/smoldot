// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![cfg(feature = "std")]

//! Implementation of the [`PlatformRef`] trait that leverages the operating system.
//!
//! This module contains the [`DefaultPlatform`] struct, which implements [`PlatformRef`].
//!
//! The [`DefaultPlatform`] delegates the logging to the `log` crate. In order to see log
//! messages, you should register as "logger" as documented by the `log` crate.
//! See <https://docs.rs/log>.
//!
//! # Example
//!
//! ```rust
//! use smoldot_light::{Client, platform::DefaultPlatform};
//! env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
//! let client = Client::new(DefaultPlatform::new(env!("CARGO_PKG_NAME").into(), env!("CARGO_PKG_VERSION").into()));
//! # let _: Client<_, ()> = client;  // Used in this example to infer the generic parameters of the Client
//! ```
//!

#[path = "native_webtransport.rs"]
mod native_webtransport;

use super::{
    Address, ConnectionType, IpAddr, LogLevel, MultiStreamAddress, MultiStreamWebRtcConnection,
    PlatformRef, SubstreamDirection, with_buffers,
};

use alloc::{borrow::Cow, sync::Arc};
use core::{
    fmt::{self, Write as _},
    panic,
    pin::Pin,
    str,
    time::Duration,
};
use futures_util::{FutureExt as _, future};
use parking_lot::{Condvar, Mutex};
use smoldot::libp2p::websocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    io,
    net::SocketAddr,
    thread,
    time::{Instant, UNIX_EPOCH},
};

/// Implementation of the [`PlatformRef`] trait that leverages the operating system.
pub struct DefaultPlatform {
    client_name: String,
    client_version: String,
    tasks_executor: Arc<smol::Executor<'static>>,
    shutdown_notify: event_listener::Event,
    native_webtransport: native_webtransport::Runtime,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
    tasks: Mutex<slab::Slab<future::AbortHandle>>,
    tasks_changed: Condvar,
    stopped: AtomicBool,
}

// Task panics are caught after the ownership guard is installed. Registry
// operations are atomic under their mutexes; transport state is independently owned.
impl std::panic::RefUnwindSafe for DefaultPlatform {}

impl DefaultPlatform {
    /// Creates a new [`DefaultPlatform`].
    ///
    /// This function spawns threads in order to execute the background tasks that will later be
    /// spawned.
    ///
    /// Must be passed as "client name" and "client version" that are used in various places
    /// such as to answer some JSON-RPC requests. Passing `env!("CARGO_PKG_NAME")` and
    /// `env!("CARGO_PKG_VERSION")` is typically very reasonable.
    ///
    /// # Panic
    ///
    /// Panics if it wasn't possible to spawn background threads.
    ///
    pub fn new(client_name: String, client_version: String) -> Arc<Self> {
        let tasks_executor = Arc::new(smol::Executor::new());
        let shutdown_notify = event_listener::Event::new();

        let mut workers = Vec::new();
        for n in 0..thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
        {
            // Note that `listen()` must be called here (and not in the thread being spawned), as
            // it might be notified as soon as `DefaultPlatform::new` returns.
            let on_shutdown = shutdown_notify.listen();
            let tasks_executor = tasks_executor.clone();

            let spawn_result = thread::Builder::new()
                .name(format!("smoldot-light-{}", n))
                .spawn(move || smol::block_on(tasks_executor.run(on_shutdown)));

            match spawn_result {
                Ok(worker) => workers.push(worker),
                Err(err) => {
                    shutdown_notify.notify(usize::MAX);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    panic!("Failed to spawn execution thread: {err}");
                }
            }
        }

        Arc::new(DefaultPlatform {
            client_name,
            client_version,
            tasks_executor,
            shutdown_notify,
            native_webtransport: native_webtransport::Runtime::new(),
            workers: Mutex::new(workers),
            tasks: Mutex::new(slab::Slab::new()),
            tasks_changed: Condvar::new(),
            stopped: AtomicBool::new(false),
        })
    }
    /// Stops platform-owned tasks and joins native workers.
    ///
    /// Remove the client's chains and drop its core `Client` before calling this.
    /// Call outside the platform's worker threads and outside any Python GIL.
    /// Cooperative task cancellation has a three-second deadline.
    pub fn shutdown(&self) -> io::Result<()> {
        let current = thread::current().id();
        if self
            .workers
            .lock()
            .iter()
            .any(|worker| worker.thread().id() == current)
        {
            return Err(io::Error::other(
                "platform shutdown must run outside a smoldot worker",
            ));
        }
        let handles = {
            let tasks = self.tasks.lock();
            self.stopped.store(true, Ordering::Release);
            tasks
                .iter()
                .map(|(_, handle)| handle.clone())
                .collect::<Vec<_>>()
        };
        for handle in handles {
            handle.abort();
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut tasks = self.tasks.lock();
        while !tasks.is_empty() {
            if self
                .tasks_changed
                .wait_until(&mut tasks, deadline)
                .timed_out()
                && !tasks.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "platform tasks did not stop",
                ));
            }
        }
        drop(tasks);
        self.shutdown_notify.notify(usize::MAX);
        let workers = core::mem::take(&mut *self.workers.lock());
        for worker in workers {
            worker
                .join()
                .map_err(|_| io::Error::other("smoldot worker panicked"))?;
        }
        self.native_webtransport.shutdown();
        Ok(())
    }
}

impl PlatformRef for Arc<DefaultPlatform> {
    type Delay = futures_util::future::Map<smol::Timer, fn(Instant) -> ()>;
    type Instant = Instant;
    type MultiStream = native_webtransport::Connection;
    type Stream = Stream;
    type StreamConnectFuture = future::Ready<Self::Stream>;
    type MultiStreamConnectFuture = future::Ready<MultiStreamWebRtcConnection<Self::MultiStream>>;
    type ReadWriteAccess<'a> = with_buffers::ReadWriteAccess<'a, Instant>;
    type StreamUpdateFuture<'a> = future::BoxFuture<'a, ()>;
    type StreamErrorRef<'a> = &'a io::Error;
    type NextSubstreamFuture<'a> =
        future::BoxFuture<'a, Option<(Self::Stream, SubstreamDirection)>>;

    fn now_from_unix_epoch(&self) -> Duration {
        // Intentionally panic if the time is configured earlier than the UNIX EPOCH.
        UNIX_EPOCH.elapsed().unwrap()
    }

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn fill_random_bytes(&self, buffer: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), buffer);
    }

    fn sleep(&self, duration: Duration) -> Self::Delay {
        smol::Timer::after(duration).map(|_| ())
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        smol::Timer::at(when).map(|_| ())
    }

    fn spawn_task(&self, _task_name: Cow<str>, task: impl Future<Output = ()> + Send + 'static) {
        let (handle, registration) = future::AbortHandle::new_pair();
        let id = {
            let mut tasks = self.tasks.lock();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            tasks.insert(handle)
        };
        // The guard is owned even before the first poll, so cancellation always
        // releases registration and the platform keep-alive.
        let guard = TaskGuard {
            platform: self.clone(),
            id,
        };
        self.tasks_executor
            .spawn(
                panic::AssertUnwindSafe(async move {
                    let _guard = guard;
                    let _ = future::Abortable::new(task, registration).await;
                })
                .catch_unwind(),
            )
            .detach();
    }

    fn log<'a>(
        &self,
        log_level: LogLevel,
        log_target: &'a str,
        message: &'a str,
        key_values: impl Iterator<Item = (&'a str, &'a dyn fmt::Display)>,
    ) {
        // Note that this conversion is most likely completely optimized out by the compiler due
        // to log levels having the same numerical values.
        let log_level = match log_level {
            LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Trace => log::Level::Trace,
        };

        let mut message_build = String::with_capacity(128);
        message_build.push_str(message);
        let mut first = true;
        for (key, value) in key_values {
            if first {
                let _ = write!(message_build, "; ");
                first = false;
            } else {
                let _ = write!(message_build, ", ");
            }
            let _ = write!(message_build, "{}={}", key, value);
        }

        log::logger().log(
            &log::RecordBuilder::new()
                .level(log_level)
                .target(log_target)
                .args(format_args!("{}", message_build))
                .build(),
        )
    }

    fn client_name(&'_ self) -> Cow<'_, str> {
        Cow::Borrowed(&self.client_name)
    }

    fn client_version(&'_ self) -> Cow<'_, str> {
        Cow::Borrowed(&self.client_version)
    }

    fn supports_connection_type(&self, connection_type: ConnectionType) -> bool {
        // TODO: support WebSocket secure
        matches!(
            connection_type,
            ConnectionType::TcpIpv4
                | ConnectionType::TcpIpv6
                | ConnectionType::TcpDns
                | ConnectionType::WebSocketIpv4 { .. }
                | ConnectionType::WebSocketIpv6 { .. }
                | ConnectionType::WebSocketDns { secure: false, .. }
                | ConnectionType::WebTransportIpv4
                | ConnectionType::WebTransportIpv6
        )
    }

    fn connect_stream(&self, multiaddr: Address) -> Self::StreamConnectFuture {
        let (tcp_socket_addr, host_if_websocket): (
            either::Either<SocketAddr, (String, u16)>,
            Option<String>,
        ) = match multiaddr {
            Address::TcpDns { hostname, port } => {
                (either::Right((hostname.to_string(), port)), None)
            }
            Address::TcpIp {
                ip: IpAddr::V4(ip),
                port,
            } => (either::Left(SocketAddr::from((ip, port))), None),
            Address::TcpIp {
                ip: IpAddr::V6(ip),
                port,
            } => (either::Left(SocketAddr::from((ip, port))), None),
            Address::WebSocketDns {
                hostname,
                port,
                secure: false,
            } => (
                either::Right((hostname.to_string(), port)),
                Some(format!("{}:{}", hostname, port)),
            ),
            Address::WebSocketIp {
                ip: IpAddr::V4(ip),
                port,
            } => {
                let addr = SocketAddr::from((ip, port));
                (either::Left(addr), Some(addr.to_string()))
            }
            Address::WebSocketIp {
                ip: IpAddr::V6(ip),
                port,
            } => {
                let addr = SocketAddr::from((ip, port));
                (either::Left(addr), Some(addr.to_string()))
            }

            // The API user of the `PlatformRef` trait is never supposed to open connections of
            // a type that isn't supported.
            _ => unreachable!(),
        };

        let socket_future = async {
            let tcp_socket = match tcp_socket_addr {
                either::Left(socket_addr) => smol::net::TcpStream::connect(socket_addr).await,
                either::Right((dns, port)) => smol::net::TcpStream::connect((&dns[..], port)).await,
            };

            if let Ok(tcp_socket) = &tcp_socket {
                let _ = tcp_socket.set_nodelay(true);
            }

            let socket = match (tcp_socket, host_if_websocket) {
                (Ok(tcp_socket), Some(host)) => {
                    websocket::websocket_client_handshake(websocket::Config {
                        tcp_socket,
                        host: &host,
                        url: "/",
                    })
                    .await
                    .map(TcpOrWs::Right)
                }

                (Ok(tcp_socket), None) => Ok(TcpOrWs::Left(tcp_socket)),
                (Err(err), _) => Err(err),
            };
            socket.map(future::Either::Left)
        };

        future::ready(Stream(with_buffers::WithBuffers::new(Box::pin(
            socket_future,
        ))))
    }

    fn connect_multistream(&self, address: MultiStreamAddress) -> Self::MultiStreamConnectFuture {
        let MultiStreamAddress::WebTransport {
            ip,
            port,
            cert_hashes,
        } = address
        else {
            unreachable!("unsupported connection type")
        };
        future::ready(MultiStreamWebRtcConnection {
            connection: native_webtransport::Connection::new(
                &self.native_webtransport,
                ip,
                port,
                cert_hashes.into_owned(),
            ),
            local_tls_certificate_sha256: [0; 32],
        })
    }

    fn connect_multistream_with_peer_key(
        &self,
        address: MultiStreamAddress,
        peer_public_key: [u8; 65],
    ) -> Self::MultiStreamConnectFuture {
        let MultiStreamAddress::WebTransport { ip, port, .. } = address else {
            return self.connect_multistream(address);
        };
        let mut hashes = Vec::new();
        let identity = crate::jam_webtransport_cert::P256PeerId::from_parts(
            peer_public_key[1..33].try_into().unwrap(),
            peer_public_key[64] & 1 != 0,
        );
        match identity {
            Ok(identity) if identity.to_uncompressed_sec1() == peer_public_key => {
                hashes.extend(crate::jam_webtransport_cert::certificate_hashes(
                    &identity,
                    self.now_from_unix_epoch().as_secs(),
                ));
                hashes.extend(
                    crate::jam_webtransport_cert::legacy_0129_certificate_hashes(
                        &identity,
                        self.now_from_unix_epoch().as_secs(),
                    ),
                );
            }
            // Reject an invalid supplied identity even if its address has valid
            // certificate hashes. Never degrade to a weaker identity policy.
            _ => hashes.clear(),
        }
        future::ready(MultiStreamWebRtcConnection {
            connection: native_webtransport::Connection::new(
                &self.native_webtransport,
                ip,
                port,
                hashes,
            ),
            local_tls_certificate_sha256: [0; 32],
        })
    }

    fn open_out_substream(&self, connection: &mut Self::MultiStream) {
        connection.open();
    }

    fn next_substream<'a>(
        &self,
        connection: &'a mut Self::MultiStream,
    ) -> Self::NextSubstreamFuture<'a> {
        Box::pin(connection.next())
    }

    fn stream_reset_code(&self, error: &&io::Error) -> Option<u32> {
        native_webtransport::reset_code(error)
    }

    fn read_write_access<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Result<Self::ReadWriteAccess<'a>, &'a io::Error> {
        let stream = stream.project();
        stream.0.read_write_access(Instant::now())
    }

    fn wait_read_write_again<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Self::StreamUpdateFuture<'a> {
        let stream = stream.project();
        Box::pin(stream.0.wait_read_write_again(|when| async move {
            smol::Timer::at(when).await;
        }))
    }
}

impl Drop for DefaultPlatform {
    fn drop(&mut self) {
        self.shutdown_notify.notify(usize::MAX);
        self.native_webtransport.shutdown();
        let current = thread::current().id();
        for worker in core::mem::take(self.workers.get_mut()) {
            if worker.thread().id() != current {
                let _ = worker.join();
            }
        }
    }
}

struct TaskGuard {
    platform: Arc<DefaultPlatform>,
    id: usize,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.platform.tasks.lock().remove(self.id);
        self.platform.tasks_changed.notify_all();
    }
}

/// Implementation detail of [`DefaultPlatform`].
#[pin_project::pin_project]
pub struct Stream(
    #[pin]
    with_buffers::WithBuffers<
        future::BoxFuture<'static, Result<Socket, io::Error>>,
        Socket,
        Instant,
    >,
);

impl Stream {
    fn webtransport(stream: native_webtransport::Stream) -> Self {
        Self(with_buffers::WithBuffers::new(Box::pin(future::ready(Ok(
            future::Either::Right(stream),
        )))))
    }
}

type Socket = future::Either<TcpOrWs, native_webtransport::Stream>;

type TcpOrWs = future::Either<smol::net::TcpStream, websocket::Connection<smol::net::TcpStream>>;

#[cfg(test)]
mod tests {
    use super::{DefaultPlatform, PlatformRef as _};

    #[test]
    fn tasks_run_indefinitely() {
        let platform_destroyed = event_listener::Event::new();
        let (tx, mut rx) = futures_channel::oneshot::channel();

        {
            let platform = DefaultPlatform::new("".to_string(), "".to_string());
            let when_platform_destroyed = platform_destroyed.listen();
            platform.spawn_task("".into(), async move {
                when_platform_destroyed.await;
                tx.send(()).unwrap();
            })
        }

        // The platform is destroyed, but the task must still be running.
        assert!(matches!(rx.try_recv(), Ok(None)));
        platform_destroyed.notify(usize::MAX);
        assert!(matches!(smol::block_on(rx), Ok(())));
    }

    #[test]
    fn shutdown_cancels_owned_tasks_and_joins_workers() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Released(Arc<AtomicBool>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let platform = DefaultPlatform::new("test".into(), "1".into());
        let released = Arc::new(AtomicBool::new(false));
        let guard = Released(released.clone());
        platform.spawn_task("pending".into(), async move {
            let _guard = guard;
            futures_lite::future::pending::<()>().await;
        });
        platform.shutdown().unwrap();
        assert!(released.load(Ordering::Acquire));
        assert!(platform.workers.lock().is_empty());
        assert!(platform.tasks.lock().is_empty());
        platform.shutdown().unwrap();
    }
}

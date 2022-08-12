use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    io::IoSliceMut,
    mem::MaybeUninit,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Instant,
};

use crate::runtime::{default_runtime, AsyncUdpSocket, Runtime};
use bytes::{Bytes, BytesMut};
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, ServerConfig,
};
use rustc_hash::FxHashMap;
use tokio::sync::{mpsc, Notify};
use udp::{RecvMeta, UdpState, BATCH_SIZE};

use crate::{
    mutex::Mutex,
    connection::Connecting, poll_fn, work_limiter::WorkLimiter, ConnectionEvent, EndpointConfig,
    EndpointEvent, VarInt, IO_LOOP_BOUND, RECV_TIME_BOUND, SEND_TIME_BOUND,
};

use ring::rand::*;

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: Option<ClientConfig>,
    runtime: Arc<Box<dyn Runtime>>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "ring0")]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Ok(Self::new_with_runtime(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )?
        .0)
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "ring0")]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<(Self, Incoming)> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_runtime(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: impl Runtime,
    ) -> io::Result<(Self, Incoming)> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_runtime(config, server_config, socket, Box::new(runtime))
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: impl AsyncUdpSocket,
        runtime: impl Runtime,
    ) -> io::Result<(Self, Incoming)> {
        Self::new_with_runtime(config, server_config, Box::new(socket), Box::new(runtime))
    }

    fn new_with_runtime(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Box<dyn AsyncUdpSocket>,
        runtime: Box<dyn Runtime>,
    ) -> io::Result<(Self, Incoming)> {
        let runtime = Arc::new(runtime);
        let addr = socket.local_addr()?;
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(Arc::new(config), server_config.map(Arc::new)),
            addr.is_ipv6(),
            runtime.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(async {
            if let Err(e) = driver.await {
                tracing::error!("I/O error: {}", e);
            }
        }));
        Ok((
            Self {
                inner: rc.clone(),
                default_client_config: None,
                runtime,
            },
            Incoming::new(rc),
        ))
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&mut self, config: ClientConfig) {
        self.default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let config = match &self.default_client_config {
            Some(config) => config.clone(),
            None => return Err(ConnectError::NoDefaultClientConfig),
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.lock("connect_with");
        if endpoint.driver_lost {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };
        endpoint.socket.connect(addr);

        let mut config0 = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config0.set_application_protos(&[b"hq-29"]).unwrap();
        config0.verify_peer(false);
        config0.set_max_idle_timeout(10000);
        config0.set_max_recv_udp_payload_size(1350);
        config0.set_max_send_udp_payload_size(1350);
        config0.set_initial_max_data(10_000_000);
        config0.set_initial_max_stream_data_bidi_local(1_000_000);
        config0.set_initial_max_stream_data_bidi_remote(1_000_000);
        config0.set_initial_max_stream_data_uni(1_000_000);
        config0.set_initial_max_streams_bidi(100);
        config0.set_initial_max_streams_uni(100);
        config0.set_disable_active_migration(true);
        config0.enable_early_data();
        config0.enable_dgram(true, 1000, 1000);

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid).into_owned();

        let local_addr = endpoint.socket.local_addr().unwrap();

        let mut conn1 = quiche::connect(
            Some(server_name),
            &scid,
            local_addr,
            addr,
            &mut config0,
        )
        .unwrap();
        let ch = ConnectionHandle(endpoint.next_connection_id);
        endpoint.next_connection_id += 1;

        let (ch, conn) = endpoint.inner.connect(config, addr, server_name)?;

        endpoint.connection_ids.insert(scid, ch);

        let udp_state = endpoint.udp_state.clone();
        Ok(endpoint
            .connections
            .insert(ch, conn, conn1, false, udp_state, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let socket = self.runtime.wrap_udp_socket(socket)?;
        let mut inner = self.inner.lock("rebind");
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();

        // Generate some activity so peers notice the rebind
        for sender in inner.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Ping);
        }

        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .lock("set_server_config")
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.lock("local_addr").socket.local_addr()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.lock("close");
        endpoint.connections.close = Some((error_code, reason.clone()));
        for sender in endpoint.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        if let Some(task) = endpoint.incoming_reader.take() {
            task.wake();
        }
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] and dropping the [`Incoming`] stream if
    /// that is desired.
    ///
    /// [`close()`]: Endpoint::close
    /// [`Incoming`]: crate::Incoming
    pub async fn wait_idle(&self) {
        loop {
            let idle;
            {
                let endpoint = &mut *self.inner.lock("wait_idle");
                if endpoint.connections.is_empty() {
                    break;
                }
                // Clone the `Arc<Notify>` so we can wait on the underlying `Notify` without holding
                // the lock. Store it in the outer scope to ensure it outlives the lock guard.
                idle = endpoint.idle.clone();
                // Construct the future while the lock is held to ensure we can't miss a wakeup if
                // the `Notify` is signaled immediately after we release the lock. `await` it after
                // the lock guard is out of scope.
                idle.notified()
            }
            .await;
        }
    }
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when the `Incoming` stream and all clones of the `Endpoint`
/// have been dropped, or when an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    #[allow(unused_mut)] // MSRV
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut endpoint = self.0.lock("EndpointDriver::poll");
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let now = Instant::now();
        let mut keep_going = false;
        keep_going |= endpoint.drive_recv(cx, now)?;
        keep_going |= endpoint.handle_events(cx);
        keep_going |= endpoint.drive_send(cx)?;

        if !endpoint.incoming.is_empty() {
            if let Some(task) = endpoint.incoming_reader.take() {
                task.wake();
            }
        }

        if endpoint.ref_count == 0 && endpoint.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.lock("EndpointDriver::drop");
        endpoint.driver_lost = true;
        if let Some(task) = endpoint.incoming_reader.take() {
            task.wake();
        }
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.connections.senders.clear();
    }
}

type ConnectionIdMap = HashMap<quiche::ConnectionId<'static>, ConnectionHandle>;

#[derive(Debug)]
pub(crate) struct EndpointInner {
    socket: Box<dyn AsyncUdpSocket>,
    udp_state: Arc<UdpState>,
    inner: proto::Endpoint,
    incoming_dgram: VecDeque<proto::UdpDatagram>,
    outgoing: VecDeque<proto::Transmit>,
    incoming: VecDeque<Connecting>,
    incoming_reader: Option<Waker>,
    driver: Option<Waker>,
    ipv6: bool,
    next_connection_id: usize,
    connection_ids: ConnectionIdMap,
    connections: ConnectionSet,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    driver_lost: bool,
    recv_limiter: WorkLimiter,
    recv_buf: Box<[u8]>,
    send_limiter: WorkLimiter,
    idle: Arc<Notify>,
    runtime: Arc<Box<dyn Runtime>>,
}

impl EndpointInner {
    fn drive_recv<'a>(&'a mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        self.recv_limiter.start_cycle();
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs = MaybeUninit::<[IoSliceMut<'a>; BATCH_SIZE]>::uninit();
        self.recv_buf
            .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
            .enumerate()
            .for_each(|(i, buf)| unsafe {
                iovs.as_mut_ptr()
                    .cast::<IoSliceMut>()
                    .add(i)
                    .write(IoSliceMut::<'a>::new(buf));
            });
        let mut iovs = unsafe { iovs.assume_init() };
        loop {
            match self.socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter_mut()).take(msgs) {
                        let hdr = quiche::Header::from_slice(&mut buf[0..meta.len], quiche::MAX_CONN_ID_LEN).unwrap();

                        let bind_addr = self.socket.local_addr().unwrap();

                        let mut buf1 = vec![0; meta.len];
                        buf1.clone_from_slice(&buf[0..meta.len]);
                        let datagram = proto::UdpDatagram {
                            destination: SocketAddr::new(meta.dst_ip.unwrap(), bind_addr.port()),
                            source: meta.addr,
                            ecn: meta.ecn,
                            contents: buf1,
                            segment_size: None,
                        };

                        let ch = if self.connection_ids.contains_key(&hdr.dcid) {
                            *self.connection_ids.get(&hdr.dcid).unwrap()
                        } else {
                            if hdr.ty != quiche::Type::Initial {
                                tracing::error!("Packet is not Initial");
                                continue;
                            }
                            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
                            config.load_cert_chain_from_pem_file("src/cert.crt").unwrap();
                            config.load_priv_key_from_pem_file("src/cert.key").unwrap();
                            config.set_application_protos(&[b"hq-29"]).unwrap();
                            config.set_max_idle_timeout(10000);
                            config.set_max_recv_udp_payload_size(1350);
                            config.set_max_send_udp_payload_size(1350);
                            config.set_initial_max_data(10_000_000);
                            config.set_initial_max_stream_data_bidi_local(1_000_000);
                            config.set_initial_max_stream_data_bidi_remote(1_000_000);
                            config.set_initial_max_stream_data_uni(1_000_000);
                            config.set_initial_max_streams_bidi(100);
                            config.set_initial_max_streams_uni(100);
                            config.set_disable_active_migration(true);
                            config.enable_early_data();
                            config.enable_dgram(true, 1000, 1000);

                            let mut new_dcid = [0; quiche::MAX_CONN_ID_LEN];
                            SystemRandom::new().fill(&mut new_dcid[..]).unwrap();
                            let new_dcid = quiche::ConnectionId::from_vec(new_dcid.into());

                            let ch = ConnectionHandle(self.next_connection_id);
                            self.next_connection_id += 1;

                            let mut conn1 = quiche::accept(
                                &new_dcid,
                                None,
                                SocketAddr::new(meta.dst_ip.unwrap(), bind_addr.port()),
                                meta.addr,
                                &mut config,
                            )
                            .unwrap();
                            
                            let mut data: BytesMut = buf[0..meta.len].into();
                            let buf = data.split_to(meta.stride.min(data.len()));
                            if let Some((ch, DatagramEvent::NewConnection(conn))) = self.inner.handle(now, meta.addr, meta.dst_ip, meta.ecn, buf) {
                                let conn = self.connections.insert(
                                    ch,
                                    conn,
                                    conn1,
                                    true,
                                    self.udp_state.clone(),
                                    self.runtime.clone(),
                                );
                                tracing::trace!("conn={:?}", conn);
                                self.incoming.push_back(conn);

                                self.connection_ids.insert(new_dcid, ch);
                            } else {
                                self.incoming_dgram.push_back(datagram);
                                continue;
                            }
                            ch
                        };

                        while let Some(d) = self.incoming_dgram.pop_front() {
                            let _ = self
                            .connections
                            .senders
                            .get_mut(&ch)
                            .unwrap()
                            .send(ConnectionEvent::Datagram(d));
                        }
                        let _ = self
                        .connections
                        .senders
                        .get_mut(&ch)
                        .unwrap()
                        .send(ConnectionEvent::Datagram(datagram));
                    }
                }
                Poll::Pending => {
                    break;
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
            if !self.recv_limiter.allow_work() {
                self.recv_limiter.finish_cycle();
                return Ok(true);
            }
        }

        self.recv_limiter.finish_cycle();
        Ok(false)
    }

    fn drive_send(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        self.send_limiter.start_cycle();

        let result = loop {
            while self.outgoing.len() < BATCH_SIZE {
                match self.inner.poll_transmit() {
                    Some(x) => self.outgoing.push_back(x),
                    None => break,
                }
            }

            if self.outgoing.is_empty() {
                break Ok(false);
            }

            if !self.send_limiter.allow_work() {
                break Ok(true);
            }

            match self
                .socket
                .poll_send(&self.udp_state, cx, self.outgoing.as_slices().0)
            {
                Poll::Ready(Ok(n)) => {
                    self.outgoing.drain(..n);
                    // We count transmits instead of `poll_send` calls since the cost
                    // of a `sendmmsg` still linearily increases with number of packets.
                    self.send_limiter.record_work(n);
                }
                Poll::Pending => {
                    break Ok(false);
                }
                Poll::Ready(Err(e)) => {
                    break Err(e);
                }
            }
        };

        self.send_limiter.finish_cycle();
        result
    }

    fn handle_events(&mut self, cx: &mut Context) -> bool {
        use EndpointEvent::*;

        for _ in 0..IO_LOOP_BOUND {
            match self.events.poll_recv(cx) {
                Poll::Ready(Some((ch, event))) => match event {
                    Proto(e) => {
                        if e.is_drained() {
                            self.connections.senders.remove(&ch);
                            if self.connections.is_empty() {
                                self.idle.notify_waiters();
                            }
                        }
                        /*
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            // Ignoring errors from dropped connections that haven't yet been cleaned up
                            let _ = self
                                .connections
                                .senders
                                .get_mut(&ch)
                                .unwrap()
                                .send(ConnectionEvent::Proto(event));
                        }*/
                    }
                    Transmit(t) => {
                        self.outgoing.push_back(t);
                    },
                },
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        conn1: quiche::Connection,
        is_server: bool,
        udp_state: Arc<UdpState>,
        runtime: Arc<Box<dyn Runtime>>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, ref reason)) = self.close {
            send.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        self.senders.insert(handle, send);
        Connecting::new(handle, conn, conn1, is_server, self.sender.clone(), recv, udp_state, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

/// Stream of incoming connections.
#[derive(Debug)]
pub struct Incoming(EndpointRef);

impl Incoming {
    pub(crate) fn new(inner: EndpointRef) -> Self {
        Self(inner)
    }
}

impl Incoming {
    /// Fetch the next incoming connection, or `None` if the endpoint has been closed
    pub async fn next(&mut self) -> Option<Connecting> {
        poll_fn(move |cx| self.poll(cx)).await
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Option<Connecting>> {
        let endpoint = &mut *self.0.lock("Incoming::poll");
        if endpoint.driver_lost {
            Poll::Ready(None)
        } else if let Some(conn) = endpoint.incoming.pop_front() {
            Poll::Ready(Some(conn))
        } else if endpoint.connections.close.is_some() {
            Poll::Ready(None)
        } else {
            endpoint.incoming_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[cfg(feature = "futures-core")]
impl futures_core::Stream for Incoming {
    type Item = Connecting;

    #[allow(unused_mut)] // MSRV
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.poll(cx)
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.lock("Incoming::drop");
        endpoint.inner.reject_new_connections();
        endpoint.incoming_reader = None;
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<Mutex<EndpointInner>>);

impl EndpointRef {
    pub(crate) fn new(
        socket: Box<dyn AsyncUdpSocket>,
        inner: proto::Endpoint,
        ipv6: bool,
        runtime: Arc<Box<dyn Runtime>>,
    ) -> Self {
        let udp_state = Arc::new(UdpState::new());
        let recv_buf = vec![
            0;
            inner.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * udp_state.gro_segments()
                * BATCH_SIZE
        ];
        let (sender, events) = mpsc::unbounded_channel();
        Self(Arc::new(Mutex::new(EndpointInner {
            socket,
            udp_state,
            inner,
            ipv6,
            events,
            incoming_dgram: VecDeque::new(),
            outgoing: VecDeque::new(),
            incoming: VecDeque::new(),
            incoming_reader: None,
            driver: None,
            next_connection_id: 0,
            connection_ids: ConnectionIdMap::new(),
            connections: ConnectionSet {
                senders: FxHashMap::default(),
                sender,
                close: None,
            },
            ref_count: 0,
            driver_lost: false,
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
            send_limiter: WorkLimiter::new(SEND_TIME_BOUND),
            idle: Arc::new(Notify::new()),
            runtime,
        })))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.lock("EndpointRef::clone").ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.lock("EndpointRef::drop");
        if let Some(x) = endpoint.ref_count.checked_sub(1) {
            endpoint.ref_count = x;
            if x == 0 {
                // If the driver is about to be on its own, ensure it can shut down if the last
                // connection is gone.
                if let Some(task) = endpoint.driver.take() {
                    task.wake();
                }
            }
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = Mutex<EndpointInner>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

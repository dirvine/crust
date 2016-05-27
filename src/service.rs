// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use maidsafe_utilities::thread::RaiiThreadJoiner;
use mio::{self, EventLoop, EventSet, PollOpt};
use net2;
use sodiumoxide;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use std::collections::HashMap;
use std::hash::{Hash, Hasher, SipHasher};
use std::io;
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use socket_addr;

use bootstrap_states::GetBootstrapContacts;
use config_handler::{self, Config};
use connection_listener::ConnectionListener;
use core::{Context, Core, CoreMessage};
use event::Event;
use error::Error;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use peer_id::{self, PeerId};
use service_discovery::ServiceDiscovery;
use static_contact_info::StaticContactInfo;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo, gen_rendezvous_info};
use nat::mapping_context::MappingContext;
use socket::Socket;
use active_connection::ActiveConnection;
use connect::establish_direct_connection::EstablishDirectConnection;
use nat::punch_hole::PunchHole;

const BOOTSTRAP_CONTEXT: Context = Context(0);
const SERVICE_DISCOVERY_CONTEXT: Context = Context(1);

const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5483;

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: io::Result<OurConnectionInfo>,
}

/// Contact info generated by a call to `Service::prepare_contact_info`.
#[derive(Debug)]
pub struct OurConnectionInfo {
    pub id: PeerId,
    pub tcp_info: PubRendezvousInfo,
    pub priv_tcp_info: PrivRendezvousInfo,
    pub tcp_socket: Option<net2::TcpBuilder>,
    pub static_contact_info: StaticContactInfo,
}

impl OurConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to peer.
    pub fn to_their_connection_info(&self) -> TheirConnectionInfo {
        TheirConnectionInfo {
            tcp_info: self.tcp_info.clone(),
            static_contact_info: self.static_contact_info.clone(),
            // tcp_addrs: self.tcp_addrs.clone(),
            id: self.id,
        }
    }
}

/// Contact info used to connect to another peer.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct TheirConnectionInfo {
    tcp_info: PubRendezvousInfo,
    static_contact_info: StaticContactInfo,
    id: PeerId,
}

impl TheirConnectionInfo {
    /// Returns the `PeerId` of the node that created this connection info.
    pub fn id(&self) -> PeerId {
        self.id
    }
}

pub type SharedConnectionMap = Arc<Mutex<HashMap<PeerId, Context>>>;

fn new_shared_connection_map() -> SharedConnectionMap {
    Arc::new(Mutex::new(HashMap::new()))
}

/// A structure representing a connection manager.
pub struct Service {
    config: Config,
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    is_listenner_running: bool,
    is_service_discovery_running: bool,
    mapping_context: Arc<MappingContext>,
    mio_tx: mio::Sender<CoreMessage>,
    name_hash: u64,
    our_keys: (PublicKey, SecretKey),
    our_contact_info: Arc<Mutex<StaticContactInfo>>,
    _thread_joiner: RaiiThreadJoiner,
}

impl Service {
    /// Constructs a service.
    pub fn new(event_tx: ::CrustEventSender) -> Result<Self, Error> {
        Service::with_config(event_tx, try!(config_handler::read_config_file()))
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(event_tx: ::CrustEventSender, config: Config) -> Result<Service, Error> {
        sodiumoxide::init();

        let mut event_loop = try!(EventLoop::new());
        let mio_tx = event_loop.channel();
        let our_keys = box_::gen_keypair();
        let name_hash = name_hash(&config.network_name);

        // Form our initial contact info
        let our_contact_info = Arc::new(Mutex::new(StaticContactInfo::default()));
        let mapping_context = MappingContext::new();

        let joiner = RaiiThreadJoiner::new(thread!("Crust event loop", move || {
            let mut core = Core::with_context_counter(2);
            event_loop.run(&mut core).expect("EventLoop failed to run");
        }));

        Ok(Service {
            connection_map: new_shared_connection_map(),
            config: config,
            event_tx: event_tx,
            is_listenner_running: false,
            is_service_discovery_running: false,
            mapping_context: Arc::new(mapping_context),
            mio_tx: mio_tx,
            name_hash: name_hash,
            our_keys: our_keys,
            our_contact_info: our_contact_info,
            _thread_joiner: joiner,
        })
    }

    /// Starts listening for beacon broadcasts.
    pub fn start_service_discovery(&mut self) {
        if self.is_service_discovery_running {
            return;
        } else {
            self.is_service_discovery_running = true;
        }

        let our_contact_info = self.our_contact_info.clone();
        let port = self.config
                       .service_discovery_port
                       .unwrap_or(SERVICE_DISCOVERY_DEFAULT_PORT);

        let _ = self.post(move |core, event_loop| {
            if let Err(e) = ServiceDiscovery::start(core,
                                                    event_loop,
                                                    our_contact_info,
                                                    SERVICE_DISCOVERY_CONTEXT,
                                                    port) {
                error!("Could not start ServiceDiscovery: {:?}", e);
            }
        });
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        if self.is_service_discovery_running {
            let _ = self.post(move |core, _| {
                let state = core.get_state(SERVICE_DISCOVERY_CONTEXT)
                                .expect("ServiceDiscovery not found");
                let mut state = state.borrow_mut();

                let service_discovery = match state.as_any().downcast_mut::<ServiceDiscovery>() {
                    Some(b) => b,
                    None => panic!("&ServiceDiscovery isn't a ServiceDiscovery!"),
                };

                service_discovery.set_listen(listen);
            });
        }
    }

    /// Start the bootstraping procedure.
    // TODO: accept a blacklist parameter.
    pub fn start_bootstrap(&mut self) -> Result<(), Error> {
        let config = self.config.clone();
        let our_public_key = self.our_keys.0.clone();
        let name_hash = self.name_hash;
        let connection_map = self.connection_map.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, event_loop| {
            GetBootstrapContacts::start(core,
                                        event_loop,
                                        BOOTSTRAP_CONTEXT,
                                        &config,
                                        SERVICE_DISCOVERY_CONTEXT,
                                        our_public_key,
                                        name_hash,
                                        connection_map,
                                        event_tx);
        })
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) -> Result<(), Error> {
        self.post(move |mut core, mut event_loop| {
            let _ = core.terminate_state(event_loop, BOOTSTRAP_CONTEXT);
        })
    }

    /// Starts accepting TCP connections.
    pub fn start_listening_tcp(&mut self) -> Result<(), Error> {
        // Do not create more than one listener.
        if self.is_listenner_running {
            return Ok(());
        } else {
            self.is_listenner_running = true;
        }

        let connection_map = self.connection_map.clone();
        let mapping_context = self.mapping_context.clone();
        let port = self.config.tcp_acceptor_port.unwrap_or(0);
        let our_public_key = self.our_keys.0.clone();
        let name_hash = self.name_hash;
        let our_contact_info = self.our_contact_info.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, event_loop| {
            ConnectionListener::start(core,
                                      event_loop,
                                      port,
                                      our_public_key,
                                      name_hash,
                                      connection_map,
                                      mapping_context,
                                      our_contact_info,
                                      event_tx);
        })
    }

    /// connect to peer
    pub fn connect(&mut self,
                   our_connection_info: OurConnectionInfo,
                   their_connection_info: TheirConnectionInfo)
                   -> Result<(), Error> {
        let event_tx = self.event_tx.clone();
        let connection_map = self.connection_map.clone();
        // FIXME: check this error
        let _ = self.post(move |core, event_loop| {
            let event_tx_rc = Rc::new(event_tx);
            let response_sent_rc = Rc::new(AtomicBool::new(false));

            let static_contact_info = their_connection_info.static_contact_info;
            let their_id = their_connection_info.id;
            for socket_addr::SocketAddr(addr) in static_contact_info.tcp_acceptors {
                let event_tx_rc = event_tx_rc.clone();
                let response_sent_rc = response_sent_rc.clone();
                let connection_map = connection_map.clone();
                // FIXME: check this error
                let _ = EstablishDirectConnection::start(core, event_loop, addr, their_id,
                                                 move |core, event_loop, res, peer_id|
                {
                    if !response_sent_rc.load(Ordering::Relaxed) {
                        match res {
                            Ok((token, stream)) => {
                                let socket = Socket::wrap(stream);
                                let event_tx = (&*event_tx_rc).clone();
                                let _ = event_tx.send(Event::NewPeer(Ok(()), peer_id));
                                response_sent_rc.store(true, Ordering::Relaxed);
                                ActiveConnection::start(core,
                                                        event_loop,
                                                        token,
                                                        socket,
                                                        connection_map,
                                                        their_id,
                                                        event_tx);
                            },
                            Err(e) => {
                                if let Ok(event_tx) = Rc::try_unwrap(event_tx_rc) {
                                    let _ = event_tx.send(Event::NewPeer(Err(e), their_id));
                                }
                            },
                        }
                    }
                });
            }

            if let Some(tcp_socket) = our_connection_info.tcp_socket {
                // FIXME: check this error
                let _ = PunchHole::start(core,
                                         event_loop,
                                         tcp_socket,
                                         our_connection_info.priv_tcp_info,
                                         their_connection_info.tcp_info,
                                         move |core, event_loop, stream_opt|
                {
                    match stream_opt {
                        Some(stream) => {
                            let token = core.get_new_token();
                            let context = core.get_new_context();

                            // FIXME: more ignored errors
                            let _ = core.insert_context(token, context);
                            let _ = event_loop.register(&stream, token, EventSet::all(), PollOpt::edge());

                            let socket = Socket::wrap(stream);
                            let event_tx = (&*event_tx_rc).clone();
                            let _ = event_tx.send(Event::NewPeer(Ok(()), their_id));
                            response_sent_rc.store(true, Ordering::Relaxed);
                            ActiveConnection::start(core,
                                                    event_loop,
                                                    token,
                                                    socket,
                                                    connection_map,
                                                    their_id,
                                                    event_tx);
                        },
                        None => {
                            if let Ok(event_tx) = Rc::try_unwrap(event_tx_rc) {
                                let error = io::Error::new(io::ErrorKind::Other, "Failed to punch hole");
                                let _ = event_tx.send(Event::NewPeer(Err(error), their_id));
                            }
                        },
                    }
                });
            }
        });

        Ok(())
        // let event_tx = self.event_tx.clone();
        // let connection_map = self.connection_map.clone();
        //
        // self.post(move |core, event_loop| {
        // EstablishConnection::start(core,
        // event_loop,
        // peer_contact_info,
        // connection_map,
        // event_tx);
        // })
        //
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&mut self, peer_id: PeerId) -> bool {
        let context = match self.connection_map.lock().unwrap().remove(&peer_id) {
            Some(context) => context,
            None => return false,
        };

        let _ = self.post(move |mut core, mut event_loop| {
            if let Some(state) = core.get_state(context) {
                state.borrow_mut().terminate(&mut core, &mut event_loop);
            }
        });

        true
    }

    /// sending data to a peer(according to it's u64 peer_id)
    pub fn send(&mut self, peer_id: PeerId, data: Vec<u8>) -> Result<(), Error> {
        if data.len() > ::MAX_DATA_LEN as usize {
            return Err(Error::MessageTooLarge);
        }

        let context = match self.connection_map
                                .lock()
                                .unwrap()
                                .get(&peer_id)
                                .map(|h| *h) {
            Some(context) => context,
            None => return Err(Error::PeerNotFound(peer_id)),
        };

        self.post(move |mut core, mut event_loop| {
            if let Some(state) = core.get_state(context) {
                state.borrow_mut().write(&mut core, &mut event_loop, data);
            }
        })
    }

    /// Lookup a mapped udp socket based on result_token
    // TODO: immediate return in case of sender.send() returned with NotificationError
    pub fn prepare_connection_info(&mut self, result_token: u32) {
        let event_tx = self.event_tx.clone();
        let our_pub_key = self.our_keys.0.clone();
        let static_contact_info = self.our_contact_info.lock().unwrap().clone();
        let mapping_context = self.mapping_context.clone();
        if let Err(e) = self.post(move |mut core, mut event_loop| {
            let event_tx_clone = event_tx.clone();
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
            match MappingTcpSocket::new(core,
                                        event_loop,
                                        &addr,
                                        &mapping_context,
                                        move |_, _, socket, addrs|
                {
                    let event_tx = event_tx_clone;
                    let (our_priv_tcp_info, our_pub_tcp_info) = gen_rendezvous_info(addrs);
                    let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Ok(OurConnectionInfo {
                            id: peer_id::new(our_pub_key),
                            tcp_info: our_pub_tcp_info,
                            priv_tcp_info: our_priv_tcp_info,
                            tcp_socket: Some(socket),
                            static_contact_info: static_contact_info,
                        }),
                    });
                    let _ = event_tx.send(event);
                },
            ) {
                Ok(()) => (),
                Err(e) => {
                    debug!("Error mapping tcp socket: {}", e);
                    let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Err(From::from(e)),
                    }));
                },
            };
        }) {
            let _ = self.event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                                result_token: result_token,
                                result: Err(io::Error::new(io::ErrorKind::Other,
                                                              format!("Failed to register task \
                                                                       with mio eventloop: {}", e))),
                            }));
        }
    }

    /// Returns our ID.
    pub fn id(&self) -> PeerId {
        peer_id::new(self.our_keys.0)
    }

    fn post<F>(&self, f: F) -> Result<(), Error>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static
    {
        Ok(try!(self.mio_tx.send(CoreMessage::new(f))))
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.post(|_, el| el.shutdown());
    }
}

/// Returns a hash of the network name.
fn name_hash(network_name: &Option<String>) -> u64 {
    let mut hasher = SipHasher::new();
    debug!("Network name: {:?}", network_name);
    network_name.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::thread;
    use std::iter;

    use maidsafe_utilities::event_sender::{MaidSafeObserver, MaidSafeEventCategory};
    use void::Void;
    use crossbeam;
    use rand;

    use event::Event;
    use service::Service;

    fn get_event_sender
        ()
        -> (::CrustEventSender, Receiver<MaidSafeEventCategory>, Receiver<Event>)
    {
        let (category_tx, category_rx) = mpsc::channel();
        let event_category = MaidSafeEventCategory::Crust;
        let (event_tx, event_rx) = mpsc::channel();

        (MaidSafeObserver::new(event_tx, event_category, category_tx), category_rx, event_rx)
    }

    fn timebomb<R, F>(dur: Duration, f: F) -> R
        where R: Send,
              F: Send + FnOnce() -> R
    {
        crossbeam::scope(|scope| {
            let thread_handle = thread::current();
            let (done_tx, done_rx) = mpsc::channel::<Void>();
            let jh = scope.spawn(move || {
                let ret = f();
                drop(done_tx);
                thread_handle.unpark();
                ret
            });
            thread::park_timeout(dur);
            match done_rx.try_recv() {
                Ok(x) => match x {},
                Err(mpsc::TryRecvError::Empty) => panic!("Timed out!"),
                Err(mpsc::TryRecvError::Disconnected) => jh.join(),
            }
        })
    }

    #[test]
    #[ignore]
    fn connect_two_peers() {
        timebomb(Duration::from_secs(5), || {
            let (event_tx_0, _category_rx_0, event_rx_0) = get_event_sender();
            let mut service_0 = unwrap_result!(Service::new(event_tx_0));

            let (event_tx_1, _category_rx_1, event_rx_1) = get_event_sender();
            let mut service_1 = unwrap_result!(Service::new(event_tx_1));

            service_0.prepare_connection_info(0);
            service_1.prepare_connection_info(0);

            let conn_info_result_0 = match unwrap_result!(event_rx_0.recv()) {
                Event::ConnectionInfoPrepared(conn_info_result) => conn_info_result,
                e => panic!("Unexpected message type: {:?}", e),
            };

            let conn_info_result_1 = match unwrap_result!(event_rx_1.recv()) {
                Event::ConnectionInfoPrepared(conn_info_result) => conn_info_result,
                e => panic!("Unexpected message type: {:?}", e),
            };

            let pub_info_0 = unwrap_result!(conn_info_result_0.result);
            let pub_info_1 = unwrap_result!(conn_info_result_1.result);
            let priv_info_0 = pub_info_0.to_their_connection_info();
            let priv_info_1 = pub_info_1.to_their_connection_info();

            unwrap_result!(service_0.connect(pub_info_0, priv_info_1));
            unwrap_result!(service_1.connect(pub_info_1, priv_info_0));

            let id_1 = match unwrap_result!(event_rx_0.recv()) {
                Event::NewPeer(res, id) => {
                    unwrap_result!(res);
                    id
                }
                e => panic!("Unexpected event when waiting for NewPeer: {:?}", e),
            };
            let id_0 = match unwrap_result!(event_rx_1.recv()) {
                Event::NewPeer(res, id) => {
                    unwrap_result!(res);
                    id
                }
                e => panic!("Unexpected event when waiting for NewPeer: {:?}", e),
            };

            let data_0: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
            let send_0 = data_0.clone();
            let data_1: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
            let send_1 = data_1.clone();
            unwrap_result!(service_0.send(id_1, data_0));
            unwrap_result!(service_1.send(id_0, data_1));

            let recv_1 = match unwrap_result!(event_rx_0.recv()) {
                Event::NewMessage(id, recv) => {
                    assert_eq!(id, id_1);
                    recv
                }
                e => panic!("Unexpected event when waiting for NewMessage: {:?}", e),
            };
            let recv_0 = match unwrap_result!(event_rx_1.recv()) {
                Event::NewMessage(id, recv) => {
                    assert_eq!(id, id_0);
                    recv
                }
                e => panic!("Unexpected event when waiting for NewMessage: {:?}", e),
            };

            assert_eq!(recv_0, send_0);
            assert_eq!(recv_1, send_1);
        });
    }
}

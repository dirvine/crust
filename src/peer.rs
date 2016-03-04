// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.
// This, along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

use std::collections::{HashMap, HashSet};
use std::io;
use std::io::{Cursor, Read, Write};
use std::net;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use service_discovery::ServiceDiscovery;
use rustc_serialize::{Encodable, Decodable};
use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PrecomputedKey, PublicKey, SecretKey};
use bytes::{Buf, ByteBuf, MutByteBuf, Take};
use mio::tcp::{TcpListener, TcpStream};
use mio::net::udp::UdpSocket;
use mio::{EventLoop, EventSet, Handler, NotifyError, PollOpt, Sender, Token, TryRead, TryWrite};
use nat_traversal::{MappedUdpSocket, MappingContext, PrivRendezvousInfo, PubRendezvousInfo,
                    PunchedUdpSocket, gen_rendezvous_info};
use slab::Slab;
use void::Void;
use secure_serialisation;
use maidsafe_utilities;
use static_contact_info::StaticContactInfo;
use rand;
use error::Error;
use ip::SocketAddrExt;

use event::{Event, PeerConnectionType};
use socket_addr::SocketAddr;
use connection_handler::MioMessage;


/// Every connection must initiate a handshare
/// Then switch state to awaitHandshake
#[derive(RustcEncodable, RustcDecodable)]
pub struct HandShake {
    listeners: StaticContactInfo,
    public_key: PublicKey,
    connection_type: PeerConnectionType,
}

/// socket type
pub enum Socket {
    Tcp(TcpStream),
    Udp(UdpSocket, net::SocketAddr),
}

// #[derive(PartialEq)]
enum PeerState {
    AwaitingHandshake,
    HandShakeResponse,
    Connected,
    Reading(Vec<u8>),
    Writing(Take<Cursor<Vec<Vec<u8>>>>),
    Closed,
}

// impl PeerState {
//     fn mut_read_buf(&mut self) -> &mut Vec<u8> {
//         match *self {
//             PeerState::Reading(ref mut buf) => buf,
//             _ => panic!("connection not in reading state"),
//         }
//     }
//
//     fn read_buf(&self) -> &[u8] {
//         match *self {
//             PeerState::Reading(ref buf) => buf,
//             _ => panic!("connection not in reading state"),
//         }
//     }
//
//     fn write_buf(&self) -> &Take<Cursor<Vec<u8>>> {
//         match *self {
//             PeerState::Writing(ref buf) => buf,
//             _ => panic!("connection not in writing state"),
//         }
//     }
//
//     fn mut_write_buf(&mut self) -> &mut Take<Cursor<Vec<u8>>> {
//         match *self {
//             PeerState::Writing(ref mut buf) => buf,
//             _ => panic!("connection not in writing state"),
//         }
//     }
//
//     // Looks for a data, if there is some the state is transitioned to
//     // writing
//     fn try_transition_to_writing(&mut self) {
//         if let Some(pos) = self.read_buf().iter().position(|b| *b == b'\n') {
//             // First, remove the current read buffer, replacing it with an
//             // empty Vec<u8>.
//             let buf = mem::replace(self, PeerState::Closed)
//                 .unwrap_read_buf();
//
//             // Wrap in `Cursor`, this allows Vec<u8> to act as a readable
//             // buffer
//             let buf = Cursor::new(buf);
//
//             // Transition the state to `Writing`, limiting the buffer to the
//             // new line (inclusive).
//             *self = PeerState::Writing(Take::new(buf, pos + 1));
//         }
//     }
//
//     // If the buffer being written back to the client has been consumed, switch
//     // back to the reading state. However, there already might be another line
//     // in the read buffer, so `try_transition_to_writing` is called as a final
//     // step.
//     fn try_transition_to_reading(&mut self) {
//         if !self.write_buf().has_remaining() {
//             let cursor = mem::replace(self, PeerState::Closed)
//                 .unwrap_write_buf()
//                 .into_inner();
//
//             let pos = cursor.position();
//             let mut buf = cursor.into_inner();
//
//             // Drop all data that has been written to the client
//             drain_to(&mut buf, pos as usize);
//
//             *self = PeerState::Reading(buf);
//
//             // Check for any new lines that have already been read.
//             self.try_transition_to_writing();
//         }
//     }
//
//     fn event_set(&self) -> mio::EventSet {
//         match *self {
//             PeerState::Reading(..) => mio::EventSet::readable(),
//             PeerState::Writing(..) => mio::EventSet::writable(),
//             _ => mio::EventSet::none(),
//         }
//     }
//
//     fn unwrap_read_buf(self) -> Vec<u8> {
//         match self {
//             PeerState::Reading(buf) => buf,
//             _ => panic!("connection not in reading state"),
//         }
//     }
//
//     fn unwrap_write_buf(self) -> Take<Cursor<Vec<u8>>> {
//         match self {
//             PeerState::Writing(buf) => buf,
//             _ => panic!("connection not in writing state"),
//         }
//     }
// }

struct Peer {
    socket: Socket,
    interest: EventSet,
    state: PeerState,
    tx: mpsc::Sender<Event>,
    mio_sink: Sender<MioMessage>,
    bytes_out: ByteBuf,
    outgoing: Vec<Vec<u8>>,
    data_in: ByteBuf,
    our_secret_key: Rc<SecretKey>, // Only used to create a pre_computed_key or decrypt a bootstrap
    our_public_key: Rc<PublicKey>,
    precomputed_key: Option<PrecomputedKey>,
    their_public_key: Option<PublicKey>, // may dissapear unless we do secure bootstrap
    close: bool,
    contact_info: Arc<Mutex<StaticContactInfo>>,
    token: Token, // bad we have two copies of this now
}

impl Peer {
    /// To add a Peer you MUST know it's keys
    /// pass a copy of StaticInfo to the peer.
    /// Hahdshake is sent on connect
    pub fn new(socket: Socket,
               their_pub_key: &PublicKey,
               our_secret_key: Rc<SecretKey>,
               our_public_key: Rc<PublicKey>,
               token: Token,
               service_sink: mpsc::Sender<Event>,
               mio_sink: Sender<MioMessage>,
               contact_info: Arc<Mutex<StaticContactInfo>>)
               -> Peer {

        let pre_key = secure_serialisation::precompute(their_pub_key, &*our_secret_key);
        Peer {
            socket: socket,
            interest: EventSet::readable(),
            state: PeerState::HandShakeResponse,
            tx: service_sink,
            mio_sink: mio_sink,
            bytes_out: ByteBuf::none(),
            outgoing: Vec::new(),
            data_in: ByteBuf::none(),
            our_secret_key: our_secret_key,
            our_public_key: our_public_key,
            precomputed_key: Some(pre_key),
            their_public_key: None, // may dissapear unless we do secure bootstrap
            close: false,
            contact_info: contact_info,
            token: token,
        }
    }

    /// Peer added from listener, we wait on it telling us who it is!
    /// Await the intial handshake
    fn new_unknown(socket: Socket,
                   our_secret_key: Rc<SecretKey>,
                   our_public_key: Rc<PublicKey>,
                   token: Token,
                   service_sink: mpsc::Sender<Event>,
                   mio_sink: Sender<MioMessage>,
                   contact_info: Arc<Mutex<StaticContactInfo>>)
                   -> Peer {
        Peer {
            socket: socket,
            interest: EventSet::readable(),
            state: PeerState::AwaitingHandshake,
            tx: service_sink,
            mio_sink: mio_sink,
            bytes_out: ByteBuf::none(),
            outgoing: Vec::new(),
            data_in: ByteBuf::none(),
            our_secret_key: our_secret_key,
            our_public_key: our_public_key,
            precomputed_key: None,
            their_public_key: None, // may dissapear unless we do secure bootstrap
            close: false,
            contact_info: contact_info,
            token: token,
        }

    }

    fn read_buf(&self, socket: &mut Socket, buf: &mut Vec<u8>) -> Result<usize, Error> {
        match *socket {
            Socket::Tcp(stream) => {
                let opt = try!(stream.try_read_buf(buf));
                match opt {
                    Some(size) => Ok(size),
                    None => Ok(0usize),
                }
            }
            Socket::Udp(socket, _) => {
                // let _test_socket = try!(socket.bound(sock_addr)); // check bound
                let opt = try!(socket.recv_from(buf));
                match opt {
                    Some(size) => Ok(size.0), // Ignoring who sent this !!!!! FIXME
                    // if socket_addr != ours then register a new connection ?
                    None => Ok(0usize),
                }
            }
        }
    }
    fn write_buf(&self) -> Result<usize, Error> {
        match self.socket {
            Socket::Tcp(stream) => {
                // let mut buf = Cursor::new(self.bytes_out);

                let opt = try!(stream.try_write_buf(&mut self.bytes_out));
                match opt {
                    Some(size) => Ok(size),
                    None => Ok(0usize),
                }
            }
            Socket::Udp(socket, ref sock_addr) => {
                // let _test_socket = try!(socket.bound(sock_addr)); // check bound
                let mut slice: Vec<u8>;
                self.bytes_out.read_slice(&mut slice);
                let opt = try!(socket.send_to(&mut slice, sock_addr));
                match opt {
                    Some(size) => Ok(size),
                    None => Ok(0usize),
                }
            }

        }
    }
    /// Queues message for sending, returns number of messgaes wiating to go to this peer
    pub fn send_message(&mut self, msg: &Vec<u8>, token: Token) -> Result<usize, Error> {
        if self.close {
            return Err(Error::ConnectionClosed);
        }
        let bytes = try!(self.serialise_message(msg));

        self.outgoing.push(bytes);

        if self.interest.is_readable() {
            self.interest.insert(EventSet::writable());
            self.interest.remove(EventSet::readable());
            try!(self.mio_sink
                     .send(MioMessage::Reregister(token)));
        }

        Ok(self.outgoing.len())
    }

    pub fn write(&mut self) {
        let result = match self.state {
            PeerState::AwaitingHandshake => self.write_secure_handshake(),
            PeerState::HandShakeResponse => self.write_handshake(),
            PeerState::Connected => self.write_messages(),
        };
        match result {
            Err(err) => {
                debug!("Write error on connection {:?}, error was {:?}",
                       self.token,
                       err)
            }
            Ok(_) => {}
        }
    }

    fn serialise_message<T: Encodable>(&self, msg: &T) -> Result<Vec<u8>, Error> {
        if let Some(pre_key) = self.precomputed_key {
            Ok(try!(secure_serialisation::pre_computed_serialise::<T>(msg, &pre_key)))
        } else if let Some(pub_key) = self.their_public_key {
            Ok(try!(secure_serialisation::anonymous_serialise::<T>(msg, &pub_key)))
        } else {
            Ok(try!(maidsafe_utilities::serialisation::serialise(msg)))
        }
    }

    fn get_handshake(&self, connection_type: PeerConnectionType) -> HandShake {
        HandShake {
            listeners: self.contact_info.lock().unwrap().clone(),
            public_key: *self.our_public_key,
            connection_type: connection_type,
        }
    }

    fn write_secure_handshake(&mut self) -> Result<(), Error> {
        // send our handshake first
        if let Some(ref pre_key) = self.precomputed_key {
            let handshake = try!(secure_serialisation::pre_computed_serialise::<HandShake>(
                                                    &self.get_handshake(PeerConnectionType::Full),
                                                    pre_key));
            let socket = match self.socket {
                Socket::Tcp(mut sock) => sock.write(&handshake),
                Socket::Udp(mut sock, ref sock_addr) => unimplemented!(), // sock.send_to(&handshake, sock_addr),
            };
            // Change the state
            self.state = PeerState::Connected;
            // Send the connection event
            self.tx.send(Event::NewPeer(self.token.as_usize(), PeerConnectionType::Full));
            self.interest.remove(EventSet::writable());
            self.interest.insert(EventSet::readable());
            return Ok(());
        } else {
            return Err(Error::InvalidState);
        }
    }

    fn write_handshake(&mut self) -> Result<(), Error> {
        let handshake;
        if let Some(key) = self.their_public_key {
            handshake = try!(secure_serialisation::anonymous_serialise::<HandShake>(&HandShake {
                                                                      listeners: self.contact_info.lock().unwrap().clone(),
                                                                      public_key: *self.our_public_key,
                                                                      connection_type: PeerConnectionType::Bootstrap
                                                                      },
                                                                     &key));
        } else {
            handshake = try!(maidsafe_utilities::serialisation::serialise::<HandShake>(&HandShake {
                    listeners: self.contact_info.lock().unwrap().clone(),
                    public_key: *self.our_public_key,
                    connection_type: PeerConnectionType::Bootstrap,
                }));
        }

        let socket = match self.socket {
            Socket::Tcp(mut sock) => sock.write(&handshake),
            Socket::Udp(mut sock, ref sock_addr) => unimplemented!(), // sock.send_to(&handshake, sock_addr),
        };


        // Change the state
        self.state = PeerState::Connected;

        // Send the connection event
        self.tx.send(Event::NewPeer(self.token.as_usize(), PeerConnectionType::Bootstrap));

        self.interest.remove(EventSet::writable());
        self.interest.insert(EventSet::readable());
        Ok(())
    }


    fn write_messages(&mut self) -> Result<(), Error> {
        loop {
            if !self.bytes_out.has_remaining() {
                if self.outgoing.len() > 0 {
                    trace!("{:?} has {} more messgages to send in queue",
                           self.token,
                           self.outgoing.len());
                    let out_buf = self.outgoing.pop(); // FIXME - take from front (deque ??)
                    self.bytes_out = ByteBuf::from_slice(&out_buf.unwrap());
                    self.outgoing.clear();
                } else {
                    // Buffer is exhausted and we have no more frames to send out.
                    trace!("{:?} wrote all bytes; switching to reading", self.token);
                    if self.close {
                        trace!("{:?} closing connection", self.token);
                        // self.socket.shutdown(Shutdown::Write);
                        self.tx.send(Event::LostPeer(self.token.as_usize()));
                    }
                    self.interest.remove(EventSet::writable());
                    self.interest.insert(EventSet::readable());
                    break;
                }
            }

            match self.write_buf() {
                Ok(write_bytes) => {
                    trace!("{:?} wrote {} bytes, messages remaining: {}",
                           self.token,
                           write_bytes,
                           self.outgoing.len());
                }
                Ok(0) => {
                    // This write call would block
                    break;
                }
                Err(e) => {
                    error!("{:?} Error occured while writing bytes: {:?}",
                           self.token,
                           e);
                    self.interest.remove(EventSet::writable());
                    self.interest.insert(EventSet::hup());
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn read(&mut self) {
        match self.state {
            PeerState::AwaitingHandshake => self.read_handshake(),
            PeerState::Connected => self.read_message(),
            _ => {}
        };
        if self.close {
            trace!("{:?} closing connection", self.token);
            // self.socket.shutdown(Shutdown::Read);
            self.tx.send(Event::LostPeer(self.token.as_usize()));
        };

    }

    fn read_message(&mut self) {
        loop {
            let mut buf = ByteBuf::mut_with_capacity(16384);
            match self.read_buf(&mut self.socket, &mut buf) {
                Err(e) => {
                    error!("{:?} Error while reading socket: {:?}", self.token, e);
                    self.interest.remove(EventSet::readable());
                    self.interest.insert(EventSet::hup());
                    return;
                }
                Ok(None) => break,
                Ok(Some(0)) => {
                    // Remote end has closed connection, we can close it now, too.
                    self.interest.remove(EventSet::readable());
                    self.interest.insert(EventSet::hup());
                    return;
                }
                Ok(Some(read_bytes)) => {
                    trace!("{:?} read {} bytes", self.token, read_bytes);
                    let mut read_buf = buf.flip();
                    loop {
                        // READ data
                    }
                    buf = read_buf.flip();
                }
            }
        }

        // Write any buffered outgoing messages
        if self.outgoing.len() > 0 {
            self.interest.remove(EventSet::readable());
            self.interest.insert(EventSet::writable());
        }
    }

    fn read_handshake(&mut self) {
        loop {
            let mut buf = [0; 2048];
            match self.socket.try_read(&mut buf) {
                Err(e) => {
                    println!("Error while reading socket: {:?}", e);
                    return;
                }
                Ok(None) => break,
                Ok(Some(_)) => {
                    let is_upgrade = if let PeerState::AwaitingHandshake(ref parser_state) =
                                            self.state {
                        let mut parser = parser_state.borrow_mut();
                        parser.parse(&buf);
                        parser.is_upgrade()
                    } else {
                        false
                    };

                    if is_upgrade {
                        // Change the current state
                        self.state = PeerState::HandshakeResponse;

                        // Change current interest to `Writable`
                        self.interest.remove(EventSet::readable());
                        self.interest.insert(EventSet::writable());
                        break;
                    }
                }
            }
        }
    }
}

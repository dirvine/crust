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
use std::net;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use service_discovery::ServiceDiscovery;
use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PrecomputedKey, PublicKey, SecretKey};
use bytes::{Buf, ByteBuf, MutByteBuf};
use mio::tcp::{TcpListener, TcpStream};
use mio::udp::UdpSocket;
use mio::{EventLoop, EventSet, Handler, NotifyError, PollOpt, Sender, Token};
use nat_traversal::{MappedUdpSocket, MappingContext, PrivRendezvousInfo, PubRendezvousInfo,
                    PunchedUdpSocket, gen_rendezvous_info};
use slab::Slab;
use void::Void;
use secure_serialisation;
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
    public_key: Option<PublicKey>,
    connection_type: PeerConnectionType,
}

/// socket type
pub enum Socket {
    Tcp(TcpStream), // TODO - use socket make stream later (nat_traversal)
    Udp(UdpSocket),
}

#[derive(PartialEq)]
enum PeerState {
    AwaitingHandshake,
    HadShakeRresponse,
    Connected,
}

struct Peer {
    socket: Socket,
    interest: EventSet,
    state: PeerState,
    tx: mpsc::Sender<Event>,
    bytes_out: ByteBuf,
    outgoing: Vec<u8>,
    data_in: ByteBuf,
    our_Secret_key: &SecretKey,
    precomputed_key: Option<PrecomputedKey>,
    their_public_key: Option<PublicKey>, // may dissapear unless we do secure bootstrap
    close: bool,
    constact_info: StaticContactInfo, // TODO - do not keep this copy here!!
}

impl Peer {
    /// To add a Peer you MUST know it's keys
    /// pass a copy of StaticInfo to the peer.
    /// Hahdshake is sent on connect
    pub fn new(socket: Socket,
               their_pub_key: &PublicKey,
               our_secret_key: &SecretKey,
               token: Token,
               service_sink: mpsc::Sender<Vec<u8>>,
               mio_sink: Sender<MioMessage>,
               contact_info: StaticContactInfo)
               -> Peer {

        let pre_key = secure_serialisation::precompute(their_pub_key, our_secret_key);
        let peer = Peer {
            socket: socket,
            interest: EventSet::readable(),
            state: PeerState::HandshakeResponse,
            tx: service_sink,
            bytes_out: ByteBuf::neww(),
            outgoing: Vec::new(),
            data_in: ByteBuf::new(),
            our_Secret_key: &SecretKey,
            precomputed_key: pre_key,
            their_public_key: None, // may dissapear unless we do secure bootstrap
            close: false,
            constact_info: contact_info,
        };
    }

    /// Peer added from listener, we wait on it telling us who it is!
    /// Await the intial handshake
    fn new_unknown(socket: Socket,
                   token: Token,
                   service_sink: mpsc::Sender<Vec<u8>>,
                   mio_sink: Sender<MioMessage>,
                   contact_info: StaticContactInfo)
                   -> Peer {
        Peer {
            socket: socket,
            interest: EventSet::readable(),
            state: PeerState::AwaitingHandshake,
            tx: service_sink,
            bytes_out: ByteBuf::neww(),
            outgoing: Vec::new(),
            data_in: ByteBuf::new(),
            precomputed_key: None,
            their_public_key: None, // may dissapear unless we do secure bootstrap
            close: false,
            contact_info: contact_info,
        }

    }

    /// Queues message for sending, returns number of messgaes wiating to go to this peer
    pub fn send_message(&mut self, msg: &[u8]) -> Result<usize, Error> {
        if self.closed {
            return Error::ConnectionClosed;
        }
        let bytes = try!(self.serialise_message(msg));

        self.outgoing.push(bytes);

        if self.interest.is_readable() {
            self.interest.insert(EventSet::writable());
            self.interest.remove(EventSet::readable());
            try!(self.event_loop_tx
                     .send(MioMessage::Reregister(self.token)));
        }

        Ok(self.outgoing.len())
    }

    pub fn write(&mut self) {
        match self.state {
            PeerState::AwaitingHandshake => self.write_secure_handshake(),
            PeerState::HandshakeResponse => self.write_handshake(),
            PeerState::Connected => self.write_messages(),
            _ => {}
        }
    }

    fn serialise_message(&self, msg: &[u8]) -> Result<&[u8], Error> {
        if let Some(pre_key) = self.precomputed_key {
            try!(secure_serialisation::pre_compute_serialise::<Vec<u8>>(msg, pre_key))
        } else if let Some(pub_key) = self.public_key {
            try!(secure_serialisation::anonymous_serialise::<Vec<u8>>(msg, pub_key))
        } else {
            try!(maidsafe_utilities::Serialistaion::serialise(msg))
        }
    }

    fn write_secure_handshake(&mut self) {
        // send our handshake first
        let handshake =
            secure_serialisation::pre_computed_serialise::<HandShake>(&contact_info,
                                                                      &self.pre_key,
                                                                      PeerConnectionType::Full);
        self.socket.try_write(handshake);
        self.interest.remove(EventSet::writable());
        self.interest.insert(EventSet::readable());
    }

    fn write_handshake(&mut self) {

        self.socket.try_write(response.as_bytes()).unwrap();

        // Change the state
        self.state = PeerState::Connected;

        // Send the connection event
        self.tx.send(Message::Connect(self.token));

        self.interest.remove(EventSet::writable());
        self.interest.insert(EventSet::readable());
    }


    fn write_messages(&mut self) {
        loop {
            if !self.bytes_out.has_remaining() {
                if self.outgoing.len() > 0 {
                    trace!("{:?} has {} more messgages to send in queue",
                           self.token,
                           self.outgoing.len());
                    let out_buf = self.serialize_frames();
                    self.bytes_out = ByteBuf::from_slice(&*out_buf);
                    self.outgoing.clear();
                } else {
                    // Buffer is exhausted and we have no more frames to send out.
                    trace!("{:?} wrote all bytes; switching to reading", self.token);
                    if self.close {
                        trace!("{:?} closing connection", self.token);
                        self.socket.shutdown(Shutdown::Write);
                        self.tx.send(Event::LostPeer(self.token));
                    }
                    self.interest.remove(EventSet::writable());
                    self.interest.insert(EventSet::readable());
                    break;
                }
            }

            match self.socket.try_write_buf(&mut self.outgoing_bytes) {
                Ok(Some(write_bytes)) => {
                    trace!("{:?} wrote {} bytes, remaining: {}",
                           self.token,
                           write_bytes,
                           self.outgoing_bytes.remaining());
                }
                Ok(None) => {
                    // This write call would block
                    break;
                }
                Err(e) => {
                    error!("{:?} Error occured while writing bytes: {}", self.token, e);
                    self.interest.remove(EventSet::writable());
                    self.interest.insert(EventSet::hup());
                    break;
                }
            }
        }
    }

    pub fn read(&mut self) {
        match self.state {
            PeerState::AwaitingHandshake(_) => self.read_handshake(),
            PeerState::Connected => self.read_message(),
            _ => {}
        };
        if self.close {
            trace!("{:?} closing connection", self.token);
            self.socket.shutdown(Shutdown::Write);
            self.tx.send(Event::LostPeer(self.token));
        };

    }

    fn read_message(&mut self) {
        loop {
            let mut buf = ByteBuf::mut_with_capacity(16384);
            match self.socket.try_read_buf(&mut buf) {
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

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
use std::rc::Rc;
use service_discovery::ServiceDiscovery;
use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use bytes::{Buf, ByteBuf, MutByteBuf};
use mio::tcp::{TcpListener, TcpStream};
use mio::udp::UdpSocket;
use mio::{EventLoop, EventSet, Handler, NotifyError, PollOpt, Sender, Token};
use nat_traversal::{MappedUdpSocket, MappingContext, PrivRendezvousInfo, PubRendezvousInfo,
                    PunchedUdpSocket, gen_rendezvous_info};
use slab::Slab;
use void::Void;

use rand;
use error::Error;
use ip::SocketAddrExt;

use event::Event;
use socket_addr::SocketAddr;
use peer::{Socket, Peer};
use static_contact_info::StaticContactInfo;

/// internal messages to mio event loop
pub enum MioMessage {
    Reregister(Token),
    GetPeers(mpsc::Sender<Event>),
    SendMessage(Vec<u8>),
    ShutDown,
}

/// Identify the type of connection we are after
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum PeerConnectionType {
    /// One way encrypted or plain connection only
    Bootstrap,
    /// Will not be a full node. only request relay
    Relay,
    /// A full participating ndoe
    Full,
}

pub struct ConnectionHandler {
    event_loop_tx: Sender<MioMessage>,
    tx: mpsc::Sender<Event>,
    peers: Slab<Peer, Token>,
    token_counter: usize,
    contact_info: Arc<Mutex<StaticContactInfo>>,
    our_secret_key: Rc<SecretKey>,
    our_public_key: Rc<PublicKey>,
}

impl ConnectionHandler {
    fn new(event_loop_tx: Sender<MioMessage>,
           tx: mpsc::Sender<Event>,
           token_counter: Token,
           contact_info: Arc<Mutex<StaticContactInfo>>,
           our_secret_key: Rc<SecretKey>,
           our_public_key: Rc<PublicKey>)
           -> ConnectionHandler {
        ConnectionHandler {
            event_loop_tx: event_loop_tx,
            tx: tx,
            peers: Slab::new(),
            token_counter: token_counter,
            contact_info: contact_info,
            our_secret_key: our_secret_key,
            our_public_key: our_public_key,
        }

    }
    // peers who connect to our "listeners" will be automatically added by the
    // ConnectionHandler
    fn add_peer(&mut self,
                client_socket: TcpStream,
                tx: mpsc::Sender<Event>,
                event_loop_tx: Sender<MioMessage>) {
        let token = self.next_token();
        let mut peer = Peer::new_unknown(client_socket, token, tx.clone(), event_loop_tx);
        self.clients.insert(token, peer);
    }

    pub fn get_peers(&self) -> Vec<Token> {
        self.clients.keys().cloned().collect::<Vec<_>>()
    }

    pub fn remove_peer(&mut self, tkn: &Token) -> Option<Peer> {
        self.clients.remove(tkn)
    }

    pub fn send_message(&mut self, token: Token, msg: &[u8]) -> Result<(), Error> {
        let peer = try!(self.peers.get_mut(&token));
        peer.send_message(msg)
    }

    pub fn next_token(&self) -> Token {
        let token = Token(self.token_counter);
        self.token_counter += 1;
        token
    }
}

impl Handler for ConnectionHandler {
    type Timeout = usize;
    type Message = MioMessage;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {

        if events.is_readable() {
            match token {
                TCP_LISTENER => {
                    let peer_socket = match self.socket.accept() {
                        Ok(Some((sock, addr))) => sock,
                        Ok(None) => unreachable!(),
                        Err(e) => {
                            println!("Accept error: {}", e);
                            return;
                        }
                    };

                    let new_token = self.next_token();
                    let peer_socket_ref = &peer_socket;
                    let peer = Peer::new_unknown(peer_socket,
                                                 new_token,
                                                 self.tx.clone(),
                                                 self.event_loop_tx);
                    self.peers.insert(new_token, peer);

                    event_loop.register(peer_socket_ref,
                                        new_token,
                                        EventSet::readable(),
                                        PollOpt::edge() | PollOpt::oneshot())
                              .unwrap();
                }
                token => {
                    let mut peer = self.peers.get_mut(&token).unwrap();
                    peer.read();
                    let peer_sock = match peer.socket {
                        Socket::Tcp(socket) => socket,
                        Socket::Udp(socket) => socket,
                    };
                    event_loop.reregister(&peer.sock,
                                          token,
                                          peer.interest,
                                          PollOpt::edge() | PollOpt::oneshot())
                              .unwrap();
                }
            }
        }

        if events.is_writable() {
            let mut peer = self.peers.get_mut(&token).unwrap();
            peer.write();
            event_loop.reregister(&peer.socket,
                                  token,
                                  peer.interest,
                                  PollOpt::edge() | PollOpt::oneshot())
                      .unwrap();
        }

    }



    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: MioMessage) {
        match msg {
            MioMessage::Shutdown => {
                event_loop.shutdown();
            }
        }
    }
}

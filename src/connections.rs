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

use sender_receiver::CrustMsg;
use connection::{RaiiTcpAcceptor, UtpRendezvousConnectMode};
use udp_listener::RaiiUdpListener;
use static_contact_info::StaticContactInfo;
use rand;
use config_handler::Config;
use connection::Connection;
use error::Error;
use ip::SocketAddrExt;
use connection;
use bootstrap;
use bootstrap::RaiiBootstrap;

use event::Event;
use socket_addr::SocketAddr;
use service::{Message, MioMessage};
use utp_connections;
use peer_id;
use peer_id::PeerId;
use peer::Peer;

const TCP_LISTENER: Token = Token(0);
const UDP_LISTENER: Token = Token(1);


pub struct Connections {
    pub socket: Socket,
    tx: mpsc::Sender<Message>,
    peers: HashMap<Token, Peer>,
    token_counter: usize,
}

impl Connections {
    pub fn new(socket: Socket, tx: mpsc::Sender<Message>) -> Connections {
        Connections {
            socket: socket,
            tx: tx,
            token_counter: 2,
            clients: HashMap::new(),
        }
    }

    fn add_peer(&mut self,
                client_socket: TcpStream,
                tx: mpsc::Sender<Message>,
                event_loop_tx: Sender<MioMessage>)
                -> Token {
        let new_token = Token(self.token_counter);
        self.token_counter += 1;

        self.clients.insert(new_token,
                            WebSocketClient::new(client_socket,
                                                 new_token,
                                                 tx.clone(),
                                                 event_loop_tx));
        new_token
    }

    pub fn get_peers(&self) -> Vec<Token> {
        self.clients.keys().cloned().collect::<Vec<_>>()
    }

    fn remove_peer(&mut self, tkn: &Token) -> Option<Peer> {
        self.clients.remove(tkn)
    }

    pub fn send_message(&mut self, token: Token, msg: &[u8]) -> Result<()> {
        let peer = try!(self.peers.get_mut(&token));
        peer.send_message(msg)
    }
}

impl Handler for Connections {
    type Timeout = usize;
    type Message = Message;

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

                    let new_token = Token(self.token_counter);
                    self.peers.insert(new_token, WebSocketpeer::new(peer_socket));
                    self.token_counter += 1;

                    event_loop.register(&self.peers[&new_token].socket,
                                        new_token,
                                        EventSet::readable(),
                                        PollOpt::edge() | PollOpt::oneshot())
                              .unwrap();
                }
                token => {
                    let mut peer = self.peers.get_mut(&token).unwrap();
                    peer.read();
                    event_loop.reregister(&peer.socket,
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



    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            MioMessage::RegisterObserver(observer) => {
                self.observers.push(observer);
            }
            MioMessage::SetBroadcastListen(status) => {
                self.broadcast_listen = status;
            }
            MioMessage::SeekPeers => {
                match self.socket
                          .send_to(&self.serialised_seek_peers_request, &self.seek_peers_on) {
                    Ok(Some(_)) => {
                        if let Err(err) = event_loop.reregister(&self.socket,
                                                                DISCOVERY,
                                                                EventSet::readable(),
                                                                PollOpt::edge() |
                                                                PollOpt::oneshot()) {
                            error!("{:?}", err);
                            event_loop.shutdown();
                        }
                    }
                    Ok(None) => {
                        if let Err(err) = event_loop.reregister(&self.socket,
                                                                SEEK_PEERS,
                                                                EventSet::writable(),
                                                                PollOpt::edge() |
                                                                PollOpt::oneshot()) {
                            error!("{:?}", err);
                            event_loop.shutdown();
                        }
                    }
                    Err(err) => {
                        error!("{:?}", err);
                        event_loop.shutdown();
                    }
                }
            }
            MioMessage::Shutdown => {
                event_loop.shutdown();
            }
        }
    }
}

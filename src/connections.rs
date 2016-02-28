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

use static_contact_info::StaticContactInfo;
use rand;
use error::Error;
use ip::SocketAddrExt;

use event::Event;
use socket_addr::SocketAddr;
use peer::Peer;
use connection_handler::ConnectionHandler;

const TCP_LISTENER: Token = Token(0);
const UDP_LISTENER: Token = Token(1);

pub struct connections {
    event_loop_tx: Sender<Event>,
    tx: mpsc::Sender<Message>,
    tcp_listening_port: u16,
    udp_lisetning_post: u16,
    discovery_listening_port: u16,
}


impl Connections {
    /// Allows a user to select preferred ports for tcp udp listeners
    /// If these are 0 then any port will be selected (from the OS)
    /// IF discovery port is set to 0 then discovery is disabled
    pub fn new(tcp_port: u16,
               udp_port: u16,
               discovery_port: u16,
               tx: mpsc::Sender<Message>)
               -> Result<Connections, Error> {

        let mut event_loop = EventLoop::new().unwrap();
        let event_loop_tx = event_loop.channel();

        thread::spawn(move || {
            let tcp_listener_socket = try!(TcpListener::bind(&format!("0.0.0.0:{}", port)[..]));
            let mut server = WebSocketServer::new(server_socket, tx);

            event_loop.register(&server.socket,
                                SERVER_TOKEN,
                                EventSet::readable(),
                                PollOpt::edge())
                      .unwrap();

            event_loop.run(&mut server).unwrap();
        });

        Connections {
            socket: socket,
            tx: tx,
            token_counter: 2,
            clients: HashMap::new(),
        }
    }

    fn listen_tcp(&self, port: u16) {}

    fn add_peer(&mut self,
                client_socket: Socket,
                secret_key: &SecretKey,
                their_public_key: &PublicKey,
                tx: mpsc::Sender<Message>,
                event_loop_tx: Sender<MioMessage>)
                -> Token {
        let new_token = Token(self.token_counter);
        self.token_counter += 1;

        self.clients.insert(new_token,
                            Peer::new(client_socket, new_token, tx.clone(), event_loop_tx));
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

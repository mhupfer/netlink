extern crate futures;
// extern crate tokio_core;
extern crate netlink;

use futures::{Future, Sink, Stream};
use netlink::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink::rtnl::{
    LinkFlags, LinkLayerType, NetlinkMessage, RtnlLinkHeader, RtnlLinkMessage, RtnlMessage,
};
use netlink::{NetlinkCodec, NetlinkFlags, NetlinkFramed, Protocol, SocketAddr, TokioSocket};

fn main() {
    let mut socket = TokioSocket::new(Protocol::Route).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    let stream = NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage>::new());
    // let mut core = tokio_core::reactor::Core::new().unwrap();

    let mut packet: NetlinkMessage = RtnlMessage::GetLink(RtnlLinkMessage {
        header: RtnlLinkHeader {
            address_family: 0, // AF_UNSPEC
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::new(),
        },
        nlas: vec![],
    }).into();
    packet.set_flags(NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST));
    packet.set_sequence_number(1);
    packet.finalize();
    let mut buf = vec![0; packet.length() as usize];
    packet.to_bytes(&mut buf[..]).unwrap();

    println!(">>> {:?}", packet);
    let stream = stream.send((packet, SocketAddr::new(0, 0))).wait().unwrap();

    stream
        .for_each(|(packet, _addr)| {
            println!("<<< {:?}", packet);
            Ok(())
        })
        .wait()
        .unwrap();
}
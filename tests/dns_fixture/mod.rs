#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

#[derive(Clone, Default)]
pub struct Zone {
    records: HashMap<String, Vec<Record>>,
    wildcard: Vec<Record>,
}

impl Zone {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: &str, ttl: u32, data: RData) {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let owner = Name::from_ascii(format!("{name}.")).unwrap();
        self.records
            .entry(name)
            .or_default()
            .push(Record::from_rdata(owner, ttl, data));
    }

    pub fn wildcard(&mut self, ttl: u32, data: RData) {
        let owner = Name::from_ascii("*.example.test.").unwrap();
        self.wildcard.push(Record::from_rdata(owner, ttl, data));
    }

    pub fn clear_wildcard(&mut self) {
        self.wildcard.clear();
    }

    pub fn test_zone() -> Self {
        let mut zone = Zone::new();
        zone.add(
            "www.example.test",
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        );
        zone.add(
            "www.example.test",
            300,
            RData::AAAA(AAAA("2001:db8::10".parse::<Ipv6Addr>().unwrap())),
        );
        zone.add(
            "mail.example.test",
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 20))),
        );
        zone.add(
            "mail.example.test",
            300,
            RData::AAAA(AAAA("2001:db8::20".parse::<Ipv6Addr>().unwrap())),
        );
        zone.add(
            "cname.example.test",
            120,
            RData::CNAME(CNAME(Name::from_ascii("target.example.test.").unwrap())),
        );
        zone.add(
            "target.example.test",
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 30))),
        );
        zone.add(
            "target.example.test",
            300,
            RData::AAAA(AAAA("2001:db8::30".parse::<Ipv6Addr>().unwrap())),
        );

        zone.wildcard(60, RData::A(A(Ipv4Addr::new(198, 51, 100, 99))));
        zone.wildcard(
            60,
            RData::AAAA(AAAA("2001:db8:ffff::99".parse::<Ipv6Addr>().unwrap())),
        );
        zone
    }

    fn answer(&self, qname: &Name, qtype: RecordType) -> (ResponseCode, Vec<Record>) {
        let key = qname.to_ascii().trim_end_matches('.').to_ascii_lowercase();

        if let Some(records) = self.records.get(&key) {
            let answers = records
                .iter()
                .filter(|record| {
                    qtype == RecordType::ANY
                        || record.record_type() == qtype
                        || record.record_type() == RecordType::CNAME
                })
                .cloned()
                .collect();
            return (ResponseCode::NoError, answers);
        }

        if self.wildcard.is_empty() {
            return (ResponseCode::NXDomain, Vec::new());
        }

        let answers = self
            .wildcard
            .iter()
            .filter(|record| {
                qtype == RecordType::ANY
                    || record.record_type() == qtype
                    || record.record_type() == RecordType::CNAME
            })
            .cloned()
            .map(|mut record| {
                record.set_name(qname.clone());
                record
            })
            .collect();
        (ResponseCode::NoError, answers)
    }
}

pub struct DnsFixture {
    address: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl DnsFixture {
    pub async fn start(zone: Zone) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = socket.local_addr().unwrap();
        let zone = Arc::new(zone);
        let handle = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let response = response_for(&zone, &request);
                let Ok(bytes) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
        Self { address, handle }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn resolver_spec(&self) -> String {
        self.address.to_string()
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn response_for(zone: &Zone, request: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(true);

    let mut answers = Vec::new();
    let mut response_code = ResponseCode::NoError;
    for query in request.queries() {
        response.add_query(query.clone());
        let (code, records) = zone.answer(query.name(), query.query_type());
        response_code = code;
        answers.extend(records);
    }
    response.set_response_code(response_code);
    for answer in answers {
        response.add_answer(answer);
    }
    response
}

//! Send a TSIG-signed RFC-2136 UPDATE via the `domain` crate. Thin
//! (network/root-bound); coverage-excluded. All selection/plan/key logic is in
//! the pure modules.

use crate::error::DnsError;
use crate::tsig::{TsigAlgorithm, TsigKey};
use crate::update::{RecordKind, UpdatePlan};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::name::Name;
use domain::base::rdata::UnknownRecordData;
use domain::base::record::{Record, Ttl};
use domain::base::MessageBuilder;
use domain::rdata::tsig::Time48;
use domain::rdata::{Aaaa, A};
use domain::tsig::{Algorithm, ClientTransaction, Key, KeyName};

/// Read and parse a BIND TSIG key file.
pub fn read_tsig_key(path: &Path) -> Result<TsigKey, DnsError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| DnsError::Config(format!("reading tsig key {}: {e}", path.display())))?;
    crate::tsig::parse_tsig_key(&text)
}

/// Build, TSIG-sign, and send an RFC-2136 UPDATE for `name` in `zone`.
pub async fn send_update(
    server: SocketAddr,
    zone: &str,
    name: &str,
    plan: &UpdatePlan,
    key: &TsigKey,
) -> Result<(), DnsError> {
    // 1. Parse zone and name into `domain` Name values.
    let zone_name: Name<Vec<u8>> = zone
        .parse()
        .map_err(|e| DnsError::Config(format!("bad zone name {zone:?}: {e}")))?;
    let rr_name: Name<Vec<u8>> = name
        .parse()
        .map_err(|e| DnsError::Config(format!("bad record name {name:?}: {e}")))?;

    // 2. Build the UPDATE message.
    //    RFC 2136 reuses the standard DNS message format:
    //      - Header:    opcode=UPDATE
    //      - Question:  zone name, type=SOA, class=IN  (the Zone Section)
    //      - Answer:    empty                           (Prerequisite Section)
    //      - Authority: delete/add records              (Update Section)
    //      - Additional: will hold the TSIG RR
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_opcode(Opcode::UPDATE);
    msg.header_mut().set_id(message_id());

    // Zone section (question): zone name, SOA, IN
    let mut msg = msg.question();
    msg.push((&zone_name, Rtype::SOA, Class::IN))
        .map_err(|e| DnsError::Send(format!("push zone question: {e}")))?;

    // Skip answer/prerequisite section (empty) → jump to authority (update section)
    let msg = msg.answer();
    let mut msg = msg.authority();

    // Delete RRset for each kind (RFC 2136 §2.5.2): class=ANY, TTL=0, RDLENGTH=0
    for kind in &plan.deletes {
        let rtype = record_kind_to_rtype(*kind);
        let rdata = UnknownRecordData::from_octets(rtype, &[] as &[u8])
            .map_err(|e| DnsError::Send(format!("build delete rdata: {e}")))?;
        let rec = Record::new(rr_name.clone(), Class::ANY, Ttl::ZERO, rdata);
        msg.push(rec)
            .map_err(|e| DnsError::Send(format!("push delete record: {e}")))?;
    }

    // Add records (RFC 2136 §2.5.1): class=IN, TTL=plan.ttl, with rdata
    for (ip, kind) in &plan.adds {
        match (ip, kind) {
            (IpAddr::V4(v4), RecordKind::A) => {
                let rdata = A::new(*v4);
                let rec = Record::new(rr_name.clone(), Class::IN, Ttl::from_secs(plan.ttl), rdata);
                msg.push(rec)
                    .map_err(|e| DnsError::Send(format!("push A record: {e}")))?;
            }
            (IpAddr::V6(v6), RecordKind::Aaaa) => {
                let rdata = Aaaa::new(*v6);
                let rec = Record::new(rr_name.clone(), Class::IN, Ttl::from_secs(plan.ttl), rdata);
                msg.push(rec)
                    .map_err(|e| DnsError::Send(format!("push AAAA record: {e}")))?;
            }
            _ => {
                return Err(DnsError::Send(format!(
                    "IP/kind mismatch: {ip} is not a {kind:?}"
                )));
            }
        }
    }

    // Move to additional section so ClientTransaction can append the TSIG RR.
    let mut msg = msg.additional();

    // 3. Build the domain::tsig::Key from our TsigKey.
    let alg = map_algorithm(key.algorithm);
    let key_name: KeyName = key
        .name
        .parse()
        .map_err(|e| DnsError::Config(format!("bad TSIG key name {:?}: {e}", key.name)))?;
    let tsig_key = Key::new(alg, &key.secret, key_name, None, None)
        .map_err(|e| DnsError::Config(format!("build TSIG key: {e}")))?;

    // 4. Sign the message in-place using ClientTransaction::request.
    let txn = ClientTransaction::request(&tsig_key, &mut msg, Time48::now())
        .map_err(|e| DnsError::Send(format!("TSIG sign: {e}")))?;

    // 5. Extract the signed bytes.
    let wire = msg.finish();

    // 6. Send via UDP and receive the response.
    let bind_addr: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("valid addr"),
        SocketAddr::V6(_) => "[::]:0".parse().expect("valid addr"),
    };
    let sock = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| DnsError::Send(format!("UDP bind: {e}")))?;
    sock.send_to(&wire, server)
        .await
        .map_err(|e| DnsError::Send(format!("UDP send: {e}")))?;

    let mut buf = vec![0u8; 4096];
    let (len, _from) =
        tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .map_err(|_| DnsError::Send("dns update: no response within 5s".into()))?
            .map_err(|e| DnsError::Send(format!("UDP recv: {e}")))?;
    buf.truncate(len);

    // 7. Authenticate the response TSIG, then check the RCODE.
    let mut response = domain::base::Message::from_octets(buf)
        .map_err(|e| DnsError::Send(format!("parse response: {e}")))?;
    txn.answer(&mut response, Time48::now())
        .map_err(|e| DnsError::Send(format!("response TSIG validation failed: {e}")))?;
    let rcode = response.header().rcode();
    if rcode != Rcode::NOERROR {
        return Err(DnsError::Send(format!(
            "DNS UPDATE rejected: RCODE={rcode}"
        )));
    }

    Ok(())
}

/// Map our `TsigAlgorithm` to `domain::tsig::Algorithm`.
fn map_algorithm(alg: TsigAlgorithm) -> Algorithm {
    match alg {
        TsigAlgorithm::HmacSha256 => Algorithm::Sha256,
        TsigAlgorithm::HmacSha512 => Algorithm::Sha512,
        TsigAlgorithm::HmacSha1 => Algorithm::Sha1,
    }
}

/// Map our `RecordKind` to `domain::base::iana::Rtype`.
fn record_kind_to_rtype(kind: RecordKind) -> Rtype {
    match kind {
        RecordKind::A => Rtype::A,
        RecordKind::Aaaa => Rtype::AAAA,
    }
}

/// Generate a per-call-varying 16-bit message ID from the current time.
/// TSIG provides the real authentication; the ID only needs to vary between
/// calls so we can match request to response on the wire.
fn message_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    u16::try_from(nanos % 65536).unwrap_or(0)
}

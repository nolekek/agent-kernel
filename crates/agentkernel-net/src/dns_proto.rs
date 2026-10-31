use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    Other(u16),
}

impl From<u16> for DnsRecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => DnsRecordType::A,
            28 => DnsRecordType::AAAA,
            other => DnsRecordType::Other(other),
        }
    }
}

impl From<DnsRecordType> for u16 {
    fn from(val: DnsRecordType) -> Self {
        match val {
            DnsRecordType::A => 1,
            DnsRecordType::AAAA => 28,
            DnsRecordType::Other(o) => o,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    Refused = 5,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
    pub raw_qname: Vec<u8>,
}

/// Parses an RFC 1035 DNS query message from a raw UDP packet buffer.
pub fn parse_dns_query(buf: &[u8]) -> Result<DnsQuery, String> {
    if buf.len() < 12 {
        return Err("DNS packet too short for header (< 12 bytes)".into());
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount == 0 {
        return Err("No questions in DNS packet".into());
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    let qname_start = offset;

    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            offset += 1; // consume null root label
            break;
        }

        if (len & 0xc0) == 0xc0 {
            // DNS compression pointer (unusual in question, but supported)
            if offset + 2 > buf.len() {
                return Err("Truncated compression pointer".into());
            }
            offset += 2;
            break;
        }

        offset += 1;
        if offset + len > buf.len() {
            return Err("Label extends beyond packet bounds".into());
        }

        let label = std::str::from_utf8(&buf[offset..offset + len])
            .map_err(|e| format!("Invalid UTF-8 in DNS label: {}", e))?;
        labels.push(label.to_string());
        offset += len;
    }

    if offset + 4 > buf.len() {
        return Err("Packet truncated before QTYPE/QCLASS".into());
    }

    let raw_qname = buf[qname_start..offset].to_vec();
    let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]).into();
    let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);

    let name = labels.join(".");

    Ok(DnsQuery {
        id,
        name,
        qtype,
        qclass,
        raw_qname,
    })
}

/// Constructs a successful DNS response packet containing A or AAAA answer records.
pub fn build_dns_response(query: &DnsQuery, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Filter IPs matching requested record type
    let matching_ips: Vec<&IpAddr> = ips
        .iter()
        .filter(|ip| match (query.qtype, ip) {
            (DnsRecordType::A, IpAddr::V4(_)) => true,
            (DnsRecordType::AAAA, IpAddr::V6(_)) => true,
            _ => false,
        })
        .collect();

    // 1. Header (12 bytes)
    // ID
    packet.extend_from_slice(&query.id.to_be_bytes());
    // Flags: QR=1 (response), AA=1, RD=1, RA=1, RCODE=0 -> 0x8180
    packet.extend_from_slice(&0x8180u16.to_be_bytes());
    // QDCOUNT: 1
    packet.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT: matching answers count
    packet.extend_from_slice(&(matching_ips.len() as u16).to_be_bytes());
    // NSCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // 2. Question section
    packet.extend_from_slice(&query.raw_qname);
    packet.extend_from_slice(&u16::from(query.qtype).to_be_bytes());
    packet.extend_from_slice(&query.qclass.to_be_bytes());

    // 3. Answer section
    for ip in matching_ips {
        // Pointer to QNAME at offset 12 (0xc00c)
        packet.extend_from_slice(&[0xc0, 0x0c]);

        match ip {
            IpAddr::V4(v4) => {
                // TYPE: A (1)
                packet.extend_from_slice(&1u16.to_be_bytes());
                // CLASS: IN (1)
                packet.extend_from_slice(&1u16.to_be_bytes());
                // TTL
                packet.extend_from_slice(&ttl.to_be_bytes());
                // RDLENGTH: 4
                packet.extend_from_slice(&4u16.to_be_bytes());
                // RDATA
                packet.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                // TYPE: AAAA (28)
                packet.extend_from_slice(&28u16.to_be_bytes());
                // CLASS: IN (1)
                packet.extend_from_slice(&1u16.to_be_bytes());
                // TTL
                packet.extend_from_slice(&ttl.to_be_bytes());
                // RDLENGTH: 16
                packet.extend_from_slice(&16u16.to_be_bytes());
                // RDATA
                packet.extend_from_slice(&v6.octets());
            }
        }
    }

    packet
}

/// Constructs a DNS error response (e.g. Refused or NameError / NXDOMAIN).
pub fn build_dns_error_response(query: &DnsQuery, rcode: DnsRcode) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // 1. Header (12 bytes)
    packet.extend_from_slice(&query.id.to_be_bytes());
    // Flags: 0x8180 | rcode
    let flags = 0x8180u16 | (rcode as u16);
    packet.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT: 1
    packet.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    // NSCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // 2. Question section
    packet.extend_from_slice(&query.raw_qname);
    packet.extend_from_slice(&u16::from(query.qtype).to_be_bytes());
    packet.extend_from_slice(&query.qclass.to_be_bytes());

    packet
}

/// Helper to serialize a standard DNS query packet (useful for client/tests).
pub fn build_dns_query_packet(id: u16, domain: &str, qtype: DnsRecordType) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired: 0x0100
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME
    for label in domain.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // terminate

    // QTYPE & QCLASS
    packet.extend_from_slice(&u16::from(qtype).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN

    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_and_build_query() {
        let packet = build_dns_query_packet(0x1337, "github.com", DnsRecordType::A);
        let parsed = parse_dns_query(&packet).expect("Query parse failed");

        assert_eq!(parsed.id, 0x1337);
        assert_eq!(parsed.name, "github.com");
        assert_eq!(parsed.qtype, DnsRecordType::A);
        assert_eq!(parsed.qclass, 1);
    }

    #[test]
    fn test_build_dns_response() {
        let packet = build_dns_query_packet(0x4242, "api.github.com", DnsRecordType::A);
        let query = parse_dns_query(&packet).unwrap();

        let ips = vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4))];
        let resp = build_dns_response(&query, &ips, 60);

        assert_eq!(resp.len(), 12 + query.raw_qname.len() + 4 + 16);
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x4242);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT = 1
    }

    #[test]
    fn test_build_dns_error_response() {
        let packet = build_dns_query_packet(0x9999, "evil.com", DnsRecordType::A);
        let query = parse_dns_query(&packet).unwrap();

        let resp = build_dns_error_response(&query, DnsRcode::Refused);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x9999);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0f, 5); // RCODE = 5 (Refused)
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT = 0
    }
}

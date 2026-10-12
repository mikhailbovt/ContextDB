//! Minimal fixed-endpoint HTTP/1.1. No DNS, TLS, redirects, retry or chunking.
//! Backend responses must have an exact bounded Content-Length.

use super::{charge, exhausted, invalid, unavailable};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

const HEADER_CAP: usize = 8192;

pub(super) fn request(
    port: u16,
    method: &'static str,
    path: &'static str,
    wire: &[u8],
    cap: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<u8>> {
    let timeout = poll_timeout(budget)?;
    charge(budget, 1, 1024)?;
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), timeout)
            .map_err(|_| unavailable("embedding endpoint is unavailable"))?;
    let header = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        wire.len()
    );
    write(&mut stream, header.as_bytes(), budget)?;
    write(&mut stream, wire, budget)?;
    charge(budget, 1, HEADER_CAP as u64)?;
    let mut header = Vec::with_capacity(HEADER_CAP);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == HEADER_CAP {
            return Err(invalid("embedding HTTP headers exceed limit"));
        }
        let mut byte = [0_u8; 1];
        read_exact(&mut stream, &mut byte, budget)?;
        header.push(byte[0]);
    }
    let header =
        std::str::from_utf8(&header).map_err(|_| invalid("embedding HTTP headers malformed"))?;
    let length = body_length(header, cap)?;
    charge(budget, 1, length as u64)?;
    let mut body = vec![0_u8; length];
    read_exact(&mut stream, &mut body, budget)?;
    budget
        .check()
        .map_err(|_| exhausted("embedding allowance exhausted"))?;
    Ok(body)
}

fn body_length(header: &str, cap: usize) -> ServiceResult<usize> {
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| invalid("embedding HTTP status missing"))?;
    if status == "HTTP/1.1 503 Service Unavailable" {
        return Err(unavailable("embedding backend is loading"));
    }
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(invalid("embedding HTTP status refused"));
    }
    let mut length = None;
    let mut json = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("embedding HTTP header malformed"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            return Err(invalid("embedding HTTP encoded response refused"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("embedding HTTP length is ambiguous"));
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| invalid("embedding HTTP length malformed"))?,
            );
        }
        if name.eq_ignore_ascii_case("content-type") {
            if json || value.split(';').next() != Some("application/json") {
                return Err(invalid("embedding HTTP content type refused"));
            }
            json = true;
        }
    }
    let length = length.ok_or_else(|| invalid("embedding HTTP length missing"))?;
    if !json || length == 0 || length > cap {
        return Err(invalid("embedding HTTP response size/type refused"));
    }
    Ok(length)
}

fn poll_timeout(budget: &QueryBudget) -> ServiceResult<Duration> {
    let micros = budget
        .remaining_timeout_micros()
        .map_err(|_| exhausted("embedding allowance exhausted"))?;
    Ok(Duration::from_micros(micros.min(5000)))
}

fn read_exact(
    stream: &mut TcpStream,
    mut into: &mut [u8],
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    while !into.is_empty() {
        stream
            .set_read_timeout(Some(poll_timeout(budget)?))
            .map_err(|_| unavailable("embedding socket timeout failed"))?;
        let take = into.len().min(4096);
        charge(budget, 1, take as u64)?;
        match stream.read(&mut into[..take]) {
            Ok(0) => return Err(invalid("embedding HTTP response interrupted")),
            Ok(read) => into = &mut into[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err(unavailable("embedding HTTP read failed")),
        }
    }
    Ok(())
}

fn write(stream: &mut TcpStream, mut bytes: &[u8], budget: &mut QueryBudget) -> ServiceResult<()> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(poll_timeout(budget)?))
            .map_err(|_| unavailable("embedding socket timeout failed"))?;
        let take = bytes.len().min(4096);
        charge(budget, 1, take as u64)?;
        match stream.write(&bytes[..take]) {
            Ok(0) => return Err(invalid("embedding HTTP request interrupted")),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err(unavailable("embedding HTTP write failed")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_ambiguous_encoded_or_oversized_body_before_allocation() {
        let valid =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(body_length(valid, 2).expect("exact bounded body"), 2);
        for bad in [
            valid.replace("Length: 2", "Length: 3"),
            valid.replace("Length: 2", "Length: 2\r\nContent-Length: 2"),
            valid.replace("Length: 2", "Length: 2\r\nTransfer-Encoding: chunked"),
            valid.replace("Length: 2", "Length: 2\r\nContent-Encoding: gzip"),
        ] {
            assert!(body_length(&bad, 2).is_err());
        }
    }
}

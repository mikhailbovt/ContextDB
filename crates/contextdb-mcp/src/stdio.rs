use std::io::{self, BufRead, Write};

use crate::{JsonRpcRequest, JsonRpcResponse, McpServer};

/// Maximum UTF-8 JSON-RPC frame accepted by the stdio adapter.
pub const MAX_MCP_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Runs the newline-delimited MCP stdio transport until EOF.
///
/// The writer receives JSON-RPC only; diagnostics must go to stderr in a
/// process wrapper. Frames are bounded before allocation can grow without
/// limit, and each response is flushed immediately.
pub fn serve_stdio<R: BufRead, W: Write>(
    server: &mut McpServer,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut reader)? {
        let response = match frame {
            Ok(bytes) => {
                // RFC 8259 permits parsers to ignore a UTF-8 BOM. Windows
                // PowerShell 5.1 emits one before the first piped object, so
                // accepting it keeps the stdio transport interoperable.
                let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
                match serde_json::from_slice::<JsonRpcRequest>(bytes) {
                    Ok(request) if request.is_notification() => continue,
                    Ok(request) => server.handle(request),
                    Err(_) => JsonRpcResponse::error(
                        serde_json::Value::Null,
                        -32700,
                        "invalid JSON-RPC JSON",
                    ),
                }
            }
            Err(()) => JsonRpcResponse::error(
                serde_json::Value::Null,
                -32600,
                "MCP frame exceeds size limit",
            ),
        };
        serde_json::to_writer(&mut writer, &response)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut frame = Vec::new();
    let mut overflow = false;
    let mut saw_any = false;
    loop {
        let (consume, reached_newline, bytes) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if !saw_any {
                    return Ok(None);
                }
                while frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
            }
            saw_any = true;
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consume = newline.map_or(available.len(), |position| position + 1);
            let data_end = newline.unwrap_or(available.len());
            (consume, newline.is_some(), available[..data_end].to_vec())
        };
        reader.consume(consume);
        if !overflow {
            if frame.len().saturating_add(bytes.len()) > MAX_MCP_LINE_BYTES {
                overflow = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&bytes);
            }
        }
        if reached_newline {
            while frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
        }
    }
}

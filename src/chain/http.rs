//! JSON-RPC over HTTPS.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy_primitives::hex;
use serde::Deserialize;
use serde_json::{Value, json};

use super::rpc::{Block, Rpc, RpcError};
use crate::id::Address;

/// The largest response accepted. The biggest read this crate makes is a
/// page of 500 commitments, a few tens of kilobytes; this leaves room for any
/// honest answer and none for a node that streams without end.
const MAX_RESPONSE: usize = 8 << 20;

/// An [`Rpc`] over HTTPS.
///
/// Requests time out, redirects are not followed — a redirect would move
/// "the chain" to a host nobody chose — and responses are size-limited.
pub struct HttpRpc {
    client: reqwest::Client,
    url: reqwest::Url,
    next_id: AtomicU64,
}

impl HttpRpc {
    /// How long a request may take unless [`with_timeout`](Self::with_timeout) says otherwise.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

    /// A transport to the node at `url`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Malformed`] unless `url` is `https`, or `http` to
    /// this machine for a local development node. Plain HTTP over a network
    /// would let anyone on the path answer for the chain.
    pub fn new(url: &str) -> Result<Self, RpcError> {
        Self::with_timeout(url, Self::DEFAULT_TIMEOUT)
    }

    /// A transport to `url` whose requests give up after `timeout`.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new); also [`RpcError::Transport`] if no HTTP client
    /// can be built on this platform.
    pub fn with_timeout(url: &str, timeout: Duration) -> Result<Self, RpcError> {
        Self::build(url, timeout, &[])
    }

    /// A transport to `url` that connects to `addresses`, at the URL's port,
    /// instead of resolving its host; requests give up after `timeout`.
    ///
    /// For applications that must resolve names themselves, such as one
    /// whose kill switch blocks DNS while its tunnel is down. TLS still
    /// verifies the certificate against the host in `url`, so a wrong
    /// address fails rather than answering for the chain.
    ///
    /// # Errors
    ///
    /// As [`with_timeout`](Self::with_timeout); also
    /// [`RpcError::Malformed`] if `addresses` is empty.
    pub fn at(url: &str, addresses: &[IpAddr], timeout: Duration) -> Result<Self, RpcError> {
        if addresses.is_empty() {
            return Err(RpcError::Malformed("no address to connect to"));
        }
        Self::build(url, timeout, addresses)
    }

    fn build(url: &str, timeout: Duration, addresses: &[IpAddr]) -> Result<Self, RpcError> {
        let url = reqwest::Url::parse(url).map_err(|_| RpcError::Malformed("not a URL"))?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        match url.scheme() {
            "https" => {}
            "http" if local => {}
            _ => return Err(RpcError::Malformed("the RPC URL must use https")),
        }
        let mut client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        #[cfg(target_os = "android")]
        {
            client = client.tls_certs_only(android_roots());
        }
        if let Some(host) = url.host_str().filter(|_| !addresses.is_empty()) {
            // reqwest takes the port from the URL; the one given here is unused.
            let resolved: Vec<SocketAddr> =
                addresses.iter().map(|&ip| SocketAddr::new(ip, 0)).collect();
            client = client.resolve_to_addrs(host, &resolved);
        }
        let client = client.build().map_err(|e| RpcError::Transport(e.into()))?;
        Ok(Self {
            client,
            url,
            next_id: AtomicU64::new(1),
        })
    }

    async fn request(&self, method: &'static str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut response = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(transport)?;
        if !response.status().is_success() {
            return Err(RpcError::Node {
                code: i64::from(response.status().as_u16()),
                message: "HTTP error".to_owned(),
            });
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if bytes.len() + chunk.len() > MAX_RESPONSE {
                return Err(RpcError::Malformed("response too large"));
            }
            bytes.extend_from_slice(&chunk);
        }

        let reply: Reply =
            serde_json::from_slice(&bytes).map_err(|_| RpcError::Malformed("not JSON-RPC"))?;
        if reply.id != Some(id) {
            return Err(RpcError::Malformed("answer to another request"));
        }
        match (reply.result, reply.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error.into_rpc_error()),
            _ => Err(RpcError::Malformed("neither a result nor an error")),
        }
    }
}

impl Rpc for HttpRpc {
    async fn chain_id(&self) -> Result<u64, RpcError> {
        quantity(&self.request("eth_chainId", json!([])).await?)
    }

    async fn block_number(&self) -> Result<u64, RpcError> {
        quantity(&self.request("eth_blockNumber", json!([])).await?)
    }

    async fn call(&self, to: Address, data: &[u8], block: Block) -> Result<Vec<u8>, RpcError> {
        let block = match block {
            Block::Latest => Value::from("latest"),
            Block::Number(n) => Value::from(format!("{n:#x}")),
        };
        let params = json!([{ "to": to.to_string(), "data": hex::encode_prefixed(data) }, block]);
        data_bytes(&self.request("eth_call", params).await?)
    }
}

impl fmt::Debug for HttpRpc {
    /// Shows the host only: an RPC URL often carries an API key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRpc")
            .field("host", &self.url.host_str().unwrap_or_default())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Reply {
    id: Option<u64>,
    result: Option<Value>,
    error: Option<ReplyError>,
}

#[derive(Deserialize)]
struct ReplyError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl ReplyError {
    /// Nodes report a revert as an error carrying the revert data.
    fn into_rpc_error(self) -> RpcError {
        match self.data.as_ref().and_then(|d| data_bytes(d).ok()) {
            Some(data) if self.message.contains("revert") => RpcError::Reverted(data),
            _ => RpcError::Node {
                code: self.code,
                message: self.message,
            },
        }
    }
}

fn transport(e: reqwest::Error) -> RpcError {
    if e.is_timeout() {
        RpcError::Timeout
    } else {
        RpcError::Transport(e.into())
    }
}

/// A JSON-RPC quantity: `0x`-prefixed hex without leading zeros.
fn quantity(v: &Value) -> Result<u64, RpcError> {
    let digits = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(RpcError::Malformed("not a quantity"))?;
    u64::from_str_radix(digits, 16).map_err(|_| RpcError::Malformed("not a quantity"))
}

/// JSON-RPC data: `0x`-prefixed hex bytes.
fn data_bytes(v: &Value) -> Result<Vec<u8>, RpcError> {
    let s = v.as_str().ok_or(RpcError::Malformed("not data"))?;
    hex::decode(s).map_err(|_| RpcError::Malformed("not data"))
}

/// Mozilla's root certificates, for Android, where reqwest's default — the
/// platform verifier — needs the app's JNI context handed to it first.
#[cfg(target_os = "android")]
fn android_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der.as_ref()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insists_on_https_off_this_machine() {
        assert!(HttpRpc::new("https://rpc.example").is_ok());
        assert!(HttpRpc::new("http://127.0.0.1:8545").is_ok());
        assert!(matches!(
            HttpRpc::new("http://rpc.example"),
            Err(RpcError::Malformed(_))
        ));
        assert!(matches!(
            HttpRpc::new("ws://rpc.example"),
            Err(RpcError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn connects_to_the_address_given() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let port = listener.local_addr().expect("bound").port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a connection");
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await;
            let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x66eee"}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.expect("written");
        });

        let url = format!("http://localhost:{port}");
        let here = [IpAddr::from([127, 0, 0, 1])];
        let rpc = HttpRpc::at(&url, &here, HttpRpc::DEFAULT_TIMEOUT).expect("a valid URL");
        assert_eq!(rpc.chain_id().await.expect("an answer"), 0x66eee);
        assert!(matches!(
            HttpRpc::at(&url, &[], HttpRpc::DEFAULT_TIMEOUT),
            Err(RpcError::Malformed(_))
        ));
    }

    #[test]
    fn keeps_the_url_out_of_debug() {
        let rpc = HttpRpc::new("https://rpc.example/v2/secret-api-key").expect("a valid URL");
        assert!(!format!("{rpc:?}").contains("secret-api-key"));
    }

    #[test]
    fn reads_quantities_and_data() {
        assert_eq!(quantity(&json!("0x66eee")).ok(), Some(421_614));
        assert!(quantity(&json!("66eee")).is_err());
        assert_eq!(data_bytes(&json!("0x0102")).ok(), Some(vec![1, 2]));
    }

    #[test]
    fn recognises_a_revert() {
        let e = ReplyError {
            code: 3,
            message: "execution reverted".to_owned(),
            data: Some(json!("0x08c379a0")),
        };
        assert!(
            matches!(e.into_rpc_error(), RpcError::Reverted(d) if d == [0x08, 0xc3, 0x79, 0xa0])
        );
    }
}
